-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Payload_Index;
package body Pkg_Supply_Map with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog;
   package GD renames Pkg_Generation_Descriptor;
   package Supply renames Pkg_Archive_Supply;
   use type Interfaces.C.unsigned; use type GD.Descriptor; use type Wide;
   Magic : constant Bytes := (78, 73, 65, 83, 77, 65, 80, 49);
   Receipt_Magic : constant Bytes := (78, 73, 65, 83, 85, 80, 48, 49);
   Max_Integer : constant Counter := 2 ** 53 - 1;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Boot : Counter;
   begin
      Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Boot, Status);
      if Status = OK and then Boot >= Deadline then Status := Stale; end if;
   end Tick;
   procedure Present (Store : MC_Store.Store; Address : Digest; Deadline : Counter; Status : out Outcome) is
      File : MC_FS.File;
   begin
      Tick (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Open_Object (Store, Address, File, Status); MC_FS.Close (File);
   exception when others => MC_FS.Close (File); Status := Indeterminate;
   end Present;
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
   function Valid (Target : Context) return Boolean is
     (Target.Root_ID /= Zero_Identity and then Target.Catalog /= Zero_Digest and then Target.Closure /= Zero_Digest
      and then (if Target.Before = GD.Empty then Target.Before_Closure = Zero_Digest
                else GD.Valid (Target.Before) and then Target.Before.Root_ID = Target.Root_ID
                  and then Target.Before_Closure /= Zero_Digest));
   function Header (Target : Context; Count : Natural) return Bytes is
      Wire : Bytes (1 .. Header_Size) := (others => 0);
   begin
      Wire (1 .. 8) := Magic; Wire (9 .. 24) := Target.Root_ID;
      if Target.Before /= GD.Empty then Wire (25 .. 56) := MC_SHA256.Hash (GD.Encode (Target.Before)); end if;
      Wire (57 .. 88) := Target.Before_Closure; Wire (89 .. 120) := Target.Catalog;
      Wire (121 .. 152) := Target.Closure; MC_Codec.Put64 (Wire, 153, Wide (Count)); return Wire;
   end Header;
   procedure Read (Store : MC_Store.Store; Address : Digest; Deadline : Counter;
      Wire : out Buffer_Access; Count : out Natural; Status : out Outcome) is
      Used, Pos : Natural; Previous : Digest := Zero_Digest;
   begin
      Wire := null; Count := 0;
      Tick (Deadline, Status); if Status /= OK then return; end if;
      Wire := new Bytes (1 .. Max_Bytes);
      MC_Store.Read_Object (Store, Address, Wire.all, Used, Status);
      if Status = OK then
         Status := Corrupt;
         if Used < Header_Size then return; end if;
         if Wire (1 .. 8) /= Magic then Status := Unsupported; return; end if;
         if Wire (9 .. 24) = Zero_Identity or else Wire (89 .. 120) = Zero_Digest
           or else Wire (121 .. 152) = Zero_Digest
           or else (Wire (25 .. 56) = Zero_Digest) /= (Wire (57 .. 88) = Zero_Digest)
           or else MC_Codec.U64 (Wire.all, 153) > Wide (Max_Entries) then return; end if;
         Count := Natural (MC_Codec.U64 (Wire.all, 153));
         if Used /= Header_Size + Entry_Size * Count then return; end if;
         for I in 1 .. Count loop
            Pos := Header_Size + Entry_Size * (I - 1);
            if Wire (Pos + 1 .. Pos + 32) <= Previous or else Wire (Pos + 33 .. Pos + 64) = Zero_Digest
              or else Wire (Pos + 65 .. Pos + 96) = Zero_Digest then return; end if;
            Previous := Wire (Pos + 1 .. Pos + 32);
         end loop;
         Tick (Deadline, Status);
      end if;
   end Read;
   procedure Receipt_References (Store : MC_Store.Store; Item : Source; Deadline : Counter;
      Wire : out Bytes; Status : out Outcome) is
      File : MC_FS.File; Used : Natural;
   begin
      Wire := (others => 0); Tick (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Read_Object (Store, Item.Receipt, Wire, Used, Status); if Status /= OK then return; end if;
      Status := Corrupt;
      if Used /= Supply.Wire_Size or else Wire (1 .. 8) /= Receipt_Magic
        or else Wire (9 .. 40) = Zero_Digest or else Wire (73 .. 104) /= Item.Original
        or else Wire (105 .. 136) /= Item.Control then return; end if;
      for I in 0 .. 2 loop
         if MC_Codec.U64 (Wire, 233 + 8 * I) not in 1 .. Wide (Max_Integer) then return; end if;
      end loop;
      if MC_Codec.U64 (Wire, 249) <= MC_Codec.U64 (Wire, 241)
        or else MC_Codec.U64 (Wire, 249) - MC_Codec.U64 (Wire, 241) > Wide (Supply.Max_Lifetime) then return; end if;
      for I in 0 .. 5 loop
         Tick (Deadline, Status); if Status /= OK then return; end if;
         if Wire (41 + 32 * I .. 72 + 32 * I) = Zero_Digest then Status := Corrupt; return; end if;
         MC_Store.Open_Object (Store, Wire (41 + 32 * I .. 72 + 32 * I), File, Status);
         MC_FS.Close (File); if Status /= OK then return; end if;
      end loop;
      Tick (Deadline, Status);
   exception when others => MC_FS.Close (File); Status := Indeterminate;
   end Receipt_References;
   procedure Evaluate (Store : in out MC_Store.Store; Target : Context; Items : Sources;
      Trusted : Authorities; Observed_At, Now, Deadline : Counter; Historical : Boolean;
      Valid_Until : out Counter; Status : out Outcome) is
      Old, After : C.Catalog; Payload : Pkg_Payload_Index.Index;
      Previous, Bound : Digest := Zero_Digest; Old_Item, Item : C.Package_Record;
      Wire : Bytes (1 .. Supply.Wire_Size); Started, Boot, Current, Elapsed, Until_Time : Counter := 0;
      Position : Natural := 0; Old_Position : Positive := 1; Which : Natural;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Clock is
      begin
         Tick (Deadline, Status); Check; MC_Clock.Boottime_Milliseconds (Boot, Status); Check;
         if Boot < Started then Status := Stale; raise Interrupted; end if;
         Elapsed := (Boot - Started) / 1_000;
         if (Boot - Started) mod 1_000 /= 0 then Elapsed := Elapsed + 1; end if;
         if not Historical and then Elapsed > Max_Integer - Now then Status := Stale; raise Interrupted; end if;
         Current := (if Historical then Now else Now + Elapsed);
         if Until_Time /= 0 and then Current >= Until_Time then Status := Stale; raise Interrupted; end if;
      end Clock;
   begin
      Valid_Until := 0; Status := Invalid_Input;
      if not Valid (Target) or else Items'Length > Max_Entries or else Trusted'Length > Max_Authorities
        or else Now not in 1 .. Max_Integer or else Observed_At not in 1 .. Now then return; end if;
      Tick (Deadline, Status); Check; MC_Clock.Boottime_Milliseconds (Started, Status); Check;
      for I in Trusted'Range loop
         if Trusted (I).Scope = Zero_Digest or else Is_Zero (Trusted (I).Key)
           or else Trusted (I).Minimum_Epoch not in 1 .. Max_Integer
           or else Trusted (I).Maximum_Age not in 1 .. Supply.Max_Lifetime then
            Status := Invalid_Input; raise Interrupted;
         end if;
         for J in Trusted'First .. I - 1 loop
            if Trusted (I).Scope = Trusted (J).Scope then Status := Conflict; raise Interrupted; end if;
         end loop;
      end loop;
      -- First check ALL upstream reference sets before any native reconstruction.
      for Source_Item of Items loop
         Clock;
         if Source_Item.Original <= Previous or else Source_Item.Control = Zero_Digest
           or else Source_Item.Receipt = Zero_Digest then Status := Corrupt; raise Interrupted; end if;
         Previous := Source_Item.Original;
         Receipt_References (Store, Source_Item, Deadline, Wire, Status); Check;
      end loop;
      for Source_Item of Items loop
         Clock; Receipt_References (Store, Source_Item, Deadline, Wire, Status); Check;
         Which := 0;
         for I in Trusted'Range loop
            if Trusted (I).Scope = Wire (9 .. 40) then Which := I; exit; end if;
         end loop;
         if Which = 0 then Status := Denied; raise Interrupted; end if;
         Clock;
         if Counter (MC_Codec.U64 (Wire, 241)) > Observed_At then Status := Stale; raise Interrupted; end if;
         if Historical then
            Supply.Recheck_Original (Store, Source_Item.Receipt, Source_Item.Original, Source_Item.Control,
               Trusted (Which), Current, Deadline, Bound, Status);
         else
            Supply.Verify_Original (Store, Source_Item.Receipt, Source_Item.Original, Source_Item.Control,
               Trusted (Which), Current, Deadline, Bound, Status);
         end if;
         Check;
         if Bound /= Source_Item.Receipt then Status := Corrupt; raise Interrupted; end if;
         declare
            Expires : constant Counter := Counter'Min (Counter (MC_Codec.U64 (Wire, 249)),
               Counter (MC_Codec.U64 (Wire, 241)) + Trusted (Which).Maximum_Age + 1);
         begin Until_Time := (if Until_Time = 0 then Expires else Counter'Min (Until_Time, Expires)); end;
         Clock;
      end loop;
      Pkg_Catalog_Retention.Verify (Store, Target.Catalog, Target.Closure, Deadline, Status); Check;
      if Target.Before /= GD.Empty then
         Present (Store, MC_SHA256.Hash (GD.Encode (Target.Before)), Deadline, Status); Check;
         Pkg_Catalog_Retention.Verify (Store, Target.Before.Catalog, Target.Before_Closure, Deadline, Status); Check;
         Pkg_Catalog_Store.Load (Store, Target.Before.Catalog, Deadline, Old, Payload, Status); Check;
      end if;
      Pkg_Catalog_Store.Load (Store, Target.Catalog, Deadline, After, Payload, Status); Check;
      -- Catalog originals are canonical sorted keys. Compare the exact difference
      -- in linear time; package names and versions never substitute for bytes.
      for I in 1 .. C.Package_Count (After) loop
         Clock; C.Read_Package (After, I, Item, Status); Check;
         while Old_Position <= C.Package_Count (Old) loop
            C.Read_Package (Old, Old_Position, Old_Item, Status); Check;
            exit when Old_Item.Original >= Item.Original;
            Old_Position := Old_Position + 1;
         end loop;
         if Old_Position > C.Package_Count (Old) or else Old_Item.Original /= Item.Original then
            -- Count consumed rows rather than incrementing an absolute index:
            -- a singleton at Positive'Last is a valid unconstrained array.
            if Position >= Items'Length or else Items (Items'First + Position).Original /= Item.Original
              or else Items (Items'First + Position).Control /= Item.Control then Status := Conflict; raise Interrupted; end if;
            Position := Position + 1;
         elsif Old_Item.Control /= Item.Control then Status := Corrupt; raise Interrupted;
         end if;
      end loop;
      if Position /= Items'Length then Status := Conflict; raise Interrupted; end if;
      Clock; Valid_Until := Until_Time; Status := OK;
   exception
      when Interrupted => Valid_Until := 0;
      when Storage_Error => Valid_Until := 0; Status := Exhausted;
      when others => Valid_Until := 0; Status := Indeterminate;
   end Evaluate;
   procedure Prepare (Store : in out MC_Store.Store; Target : Context; Items : Sources;
      Trusted : Authorities; Now, Deadline : Counter;
      Address : out Digest; Valid_Until : out Counter; Status : out Outcome) is
      Wire : Buffer_Access := null; Pos : Natural; Saved : Digest; Started, Current : Counter;
   begin
      Address := Zero_Digest; Valid_Until := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status); if Status /= OK then return; end if;
      Evaluate (Store, Target, Items, Trusted, Now, Now, Deadline, False, Valid_Until, Status);
      if Status /= OK then return; end if;
      Wire := new Bytes (1 .. Header_Size + Entry_Size * Items'Length);
      Wire (1 .. Header_Size) := Header (Target, Items'Length); Pos := Header_Size;
      for Item of Items loop
         Wire (Pos + 1 .. Pos + 32) := Item.Original; Wire (Pos + 33 .. Pos + 64) := Item.Control;
         Wire (Pos + 65 .. Pos + 96) := Item.Receipt; Pos := Pos + Entry_Size;
      end loop;
      Tick (Deadline, Status);
      if Status = OK then MC_Store.Put (Store, Wire.all, Saved, Status); end if;
      if Status = OK then
         Current_Time (Now, Started, Deadline, Current, Status);
         if Status = OK and then Valid_Until /= 0 and then Current >= Valid_Until then Status := Stale; end if;
      end if;
      if Status = OK then Address := Saved; else Valid_Until := 0; end if;
      Free (Wire);
   exception
      when Storage_Error => Free (Wire); Address := Zero_Digest; Valid_Until := 0; Status := Exhausted;
      when others => Free (Wire); Address := Zero_Digest; Valid_Until := 0; Status := Indeterminate;
   end Prepare;
   procedure Check_Map (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Observed_At, Now, Deadline : Counter; Historical : Boolean;
      Valid_Until : out Counter; Status : out Outcome) is
      Wire : Buffer_Access := null; Count, Pos : Natural; Started, Current : Counter;
   begin
      Valid_Until := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      if not Valid (Target) or else Now not in 1 .. Max_Integer or else Observed_At not in 1 .. Now
      then Status := Invalid_Input; return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status); if Status /= OK then return; end if;
      Read (Store, Address, Deadline, Wire, Count, Status);
      if Status = OK and then Wire (1 .. Header_Size) /= Header (Target, Count) then Status := Conflict; end if;
      if Status = OK then
         declare Items : Sources (1 .. Count); begin
            Pos := Header_Size;
            for Item of Items loop
               Item := (Wire (Pos + 1 .. Pos + 32), Wire (Pos + 33 .. Pos + 64), Wire (Pos + 65 .. Pos + 96));
               Pos := Pos + Entry_Size;
            end loop;
            if Historical then Current := Now; Tick (Deadline, Status);
            else Current_Time (Now, Started, Deadline, Current, Status); end if;
            if Status = OK then
               Evaluate (Store, Target, Items, Trusted, Observed_At, Current, Deadline, Historical, Valid_Until, Status);
            end if;
         end;
      end if;
      Free (Wire);
   exception
      when Storage_Error => Free (Wire); Valid_Until := 0; Status := Exhausted;
      when others => Free (Wire); Valid_Until := 0; Status := Indeterminate;
   end Check_Map;
   procedure Verify (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Now, Deadline : Counter; Valid_Until : out Counter; Status : out Outcome) is
   begin
      Check_Map (Store, Address, Target, Trusted, Now, Now, Deadline, False, Valid_Until, Status);
   end Verify;
   procedure Verify_Interval (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Observed_At, Now, Deadline : Counter;
      Valid_Until : out Counter; Status : out Outcome) is
   begin
      Check_Map (Store, Address, Target, Trusted, Observed_At, Now, Deadline, False, Valid_Until, Status);
   end Verify_Interval;
   procedure Recheck_At (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Observed_At, Deadline : Counter; Status : out Outcome) is
      Ignored : Counter;
   begin
      Check_Map (Store, Address, Target, Trusted, Observed_At, Observed_At, Deadline, True, Ignored, Status);
   end Recheck_At;
   procedure Check_Retention (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome) is
      Wire : Buffer_Access := null; Receipt : Bytes (1 .. Supply.Wire_Size); Count, Pos : Natural;
   begin
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Read (Store, Address, Deadline, Wire, Count, Status);
      if Status = OK and then (Wire (89 .. 120) /= Catalog or else Wire (121 .. 152) /= Closure) then Status := Conflict; end if;
      if Status = OK then
         for I in 0 .. 3 loop
            if Wire (25 + 32 * I .. 56 + 32 * I) /= Zero_Digest then
               Present (Store, Wire (25 + 32 * I .. 56 + 32 * I), Deadline, Status);
               exit when Status /= OK;
            end if;
         end loop;
      end if;
      if Status = OK then
         Pos := Header_Size;
         for I in 1 .. Count loop
            Receipt_References (Store, (Wire (Pos + 1 .. Pos + 32), Wire (Pos + 33 .. Pos + 64),
               Wire (Pos + 65 .. Pos + 96)), Deadline, Receipt, Status);
            exit when Status /= OK; Pos := Pos + Entry_Size;
         end loop;
      end if;
      if Status = OK then Tick (Deadline, Status); end if;
      Free (Wire);
   exception
      when Storage_Error => Free (Wire); Status := Exhausted;
      when others => Free (Wire); Status := Indeterminate;
   end Check_Retention;
end Pkg_Supply_Map;
