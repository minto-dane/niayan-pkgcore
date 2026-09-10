-- SPDX-License-Identifier: MIT
with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix;
with Pkg_Archive_Supply;
package body Pkg_Supply_Policy with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Wide; use type Pkg_Archive_Supply.Authority;
   Magic : constant Bytes := (78, 73, 65, 83, 80, 79, 76, 49);
   Max_Integer : constant Counter := 2 ** 53 - 1;
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Boot : Counter;
   begin
      Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Boot, Status);
      if Status = OK and then Boot >= Deadline then Status := Stale; end if;
   end Tick;
   procedure Current_Time (Now, Started, Deadline : Counter; Current : out Counter; Status : out Outcome) is
      Boot, Elapsed : Counter;
   begin
      Current := 0; Tick (Deadline, Status); if Status /= OK then return; end if;
      Status := Invalid_Input; if Now not in 1 .. Max_Integer then return; end if;
      MC_Clock.Boottime_Milliseconds (Boot, Status); if Status /= OK then return; end if;
      if Boot < Started then Status := Stale; return; end if;
      Elapsed := (Boot - Started) / 1_000;
      if (Boot - Started) mod 1_000 /= 0 then Elapsed := Elapsed + 1; end if;
      if Elapsed > Max_Integer - Now then Status := Stale; return; end if;
      Current := Now + Elapsed;
   end Current_Time;
   procedure Canonical (Map : Digest; Trusted : Pkg_Supply_Map.Authorities; Now : Counter;
      Value : out Snapshot; Status : out Outcome) is
      Result : Snapshot; At_Index : Natural;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Map = Zero_Digest or else Now not in 1 .. Max_Integer
        or else Trusted'Length > Pkg_Supply_Map.Max_Authorities then return; end if;
      Result.Map := Map; Result.Observed_At := Now;
      for A of Trusted loop
         if A.Scope = Zero_Digest or else Is_Zero (A.Key) or else A.Minimum_Epoch not in 1 .. Max_Integer
           or else A.Maximum_Age not in 1 .. Pkg_Archive_Supply.Max_Lifetime then return; end if;
         At_Index := Result.Count;
         while At_Index > 0 and then Result.Trusted (At_Index).Scope > A.Scope loop
            Result.Trusted (At_Index + 1) := Result.Trusted (At_Index); At_Index := At_Index - 1;
         end loop;
         if At_Index > 0 and then Result.Trusted (At_Index).Scope = A.Scope then Status := Conflict; return; end if;
         Result.Trusted (At_Index + 1) := A; Result.Count := Result.Count + 1;
      end loop;
      Value := Result; Status := OK;
   end Canonical;
   procedure Load (Store : MC_Store.Store; Address : Digest; Deadline : Counter;
      Value : out Snapshot; Status : out Outcome) is
      Wire : Bytes (1 .. Max_Bytes); Used, Pos : Natural; Result : Snapshot;
   begin
      Value := (others => <>); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Tick (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Read_Object (Store, Address, Wire, Used, Status); if Status /= OK then return; end if;
      Status := Corrupt; if Used < Header_Size then return; end if;
      if Wire (1 .. 8) /= Magic then Status := Unsupported; return; end if;
      if Wire (9 .. 40) = Zero_Digest or else MC_Codec.U64 (Wire, 41) not in 1 .. Wide (Max_Integer)
        or else MC_Codec.U64 (Wire, 49) > Wide (Pkg_Supply_Map.Max_Authorities) then return; end if;
      Result.Map := Wire (9 .. 40); Result.Observed_At := Counter (MC_Codec.U64 (Wire, 41));
      Result.Count := Natural (MC_Codec.U64 (Wire, 49));
      if Used /= Header_Size + Result.Count * Entry_Size then return; end if;
      Pos := Header_Size;
      for I in 1 .. Result.Count loop
         if Wire (Pos + 1 .. Pos + 32) = Zero_Digest or else Is_Zero (Wire (Pos + 33 .. Pos + 64))
           or else MC_Codec.U64 (Wire, Pos + 65) not in 1 .. Wide (Max_Integer)
           or else MC_Codec.U64 (Wire, Pos + 73) not in 1 .. Wide (Pkg_Archive_Supply.Max_Lifetime)
         then return; end if;
         Result.Trusted (I) := (Wire (Pos + 1 .. Pos + 32), Wire (Pos + 33 .. Pos + 64),
            Counter (MC_Codec.U64 (Wire, Pos + 65)), Counter (MC_Codec.U64 (Wire, Pos + 73)));
         if I > 1 and then Result.Trusted (I - 1).Scope >= Result.Trusted (I).Scope then return; end if;
         Pos := Pos + Entry_Size;
      end loop;
      Tick (Deadline, Status); if Status = OK then Value := Result; end if;
   exception
      when Storage_Error => Value := (others => <>); Status := Exhausted;
      when others => Value := (others => <>); Status := Indeterminate;
   end Load;
   procedure Prepare (Store : in out MC_Store.Store; Map : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter;
      Address : out Digest; Valid_Until : out Counter; Status : out Outcome) is
      Value : Snapshot; Wire : Bytes (1 .. Max_Bytes) := (others => 0); Pos : Natural;
      Started, Current : Counter; Saved : Digest;
   begin
      Address := Zero_Digest; Valid_Until := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status); if Status /= OK then return; end if;
      Canonical (Map, Trusted, Now, Value, Status); if Status /= OK then return; end if;
      Current_Time (Now, Started, Deadline, Current, Status); if Status /= OK then return; end if;
      Pkg_Supply_Map.Verify_Interval (Store, Map, Target, Trusted, Now, Current, Deadline, Valid_Until, Status);
      if Status /= OK then return; end if;
      Wire (1 .. 8) := Magic; Wire (9 .. 40) := Map; MC_Codec.Put64 (Wire, 41, Wide (Now));
      MC_Codec.Put64 (Wire, 49, Wide (Value.Count)); Pos := Header_Size;
      for I in 1 .. Value.Count loop
         Wire (Pos + 1 .. Pos + 32) := Value.Trusted (I).Scope;
         Wire (Pos + 33 .. Pos + 64) := Value.Trusted (I).Key;
         MC_Codec.Put64 (Wire, Pos + 65, Wide (Value.Trusted (I).Minimum_Epoch));
         MC_Codec.Put64 (Wire, Pos + 73, Wide (Value.Trusted (I).Maximum_Age)); Pos := Pos + Entry_Size;
      end loop;
      MC_Store.Put (Store, Wire (1 .. Pos), Saved, Status);
      if Status = OK then Current_Time (Now, Started, Deadline, Current, Status); end if;
      if Status = OK and then Valid_Until /= 0 and then Current >= Valid_Until then Status := Stale; end if;
      if Status = OK then Address := Saved; else Valid_Until := 0; end if;
   exception
      when Storage_Error => Address := Zero_Digest; Valid_Until := 0; Status := Exhausted;
      when others => Address := Zero_Digest; Valid_Until := 0; Status := Indeterminate;
   end Prepare;
   procedure Load_Trusted (Store : MC_Store.Store; Address : Digest;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter;
      Value : out Snapshot; Status : out Outcome) is
      Independent : Snapshot;
   begin
      Load (Store, Address, Deadline, Value, Status); if Status /= OK then return; end if;
      Canonical (Value.Map, Trusted, Now, Independent, Status); if Status /= OK then return; end if;
      if Value.Observed_At > Now then Status := Stale; return; end if;
      if Value.Count /= Independent.Count then Status := Denied; return; end if;
      for I in 1 .. Value.Count loop
         if Value.Trusted (I) /= Independent.Trusted (I) then Status := Denied; return; end if;
      end loop;
   end Load_Trusted;
   procedure Verify_New (Store : in out MC_Store.Store; Address : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter;
      Valid_Until : out Counter; Status : out Outcome) is
      Value : Snapshot; Started, Current : Counter;
   begin
      Valid_Until := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status); if Status /= OK then return; end if;
      Load_Trusted (Store, Address, Trusted, Now, Deadline, Value, Status); if Status /= OK then return; end if;
      Current_Time (Now, Started, Deadline, Current, Status); if Status /= OK then return; end if;
      Pkg_Supply_Map.Verify_Interval (Store, Value.Map, Target, Trusted, Value.Observed_At, Current,
         Deadline, Valid_Until, Status);
   exception
      when Storage_Error => Valid_Until := 0; Status := Exhausted;
      when others => Valid_Until := 0; Status := Indeterminate;
   end Verify_New;
   procedure Recheck_Recorded (Store : in out MC_Store.Store; Address : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter; Status : out Outcome) is
      Value : Snapshot;
   begin
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Load_Trusted (Store, Address, Trusted, Now, Deadline, Value, Status); if Status /= OK then return; end if;
      Pkg_Supply_Map.Recheck_At (Store, Value.Map, Target, Trusted, Value.Observed_At, Deadline, Status);
   exception
      when Storage_Error => Status := Exhausted;
      when others => Status := Indeterminate;
   end Recheck_Recorded;
   procedure Check_Retention (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome) is
      Value : Snapshot;
   begin
      Load (Store, Address, Deadline, Value, Status);
      if Status = OK then Pkg_Supply_Map.Check_Retention (Store, Value.Map, Catalog, Closure, Deadline, Status); end if;
   end Check_Retention;
end Pkg_Supply_Policy;
