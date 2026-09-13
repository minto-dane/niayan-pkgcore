-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Archive_Supply;
package body Pkg_Site_Supply with SPARK_Mode => Off is
   use type Byte; use type Wide; use type Word; use type Interfaces.C.unsigned;
   use type MC_FS.Entry_Kind; use type MC_FS.Entry_Info;
   Limit : constant Counter := 2 ** 53 - 1;
   Magic : constant Bytes := (78, 73, 65, 84, 82, 83, 84, 49); -- NIATRST1
   Floor_Magic : constant Bytes := (78, 73, 65, 70, 76, 79, 82, 49); -- NIAFLOR1
   procedure Decode (Wire : Bytes; Value : out Policy; Status : out Outcome) is
      Result : Policy; Pos : Natural := Header_Size;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Wire'First /= 1 or else Wire'Length < Header_Size or else Wire'Length > Maximum_Size
        or else Wire (1 .. 8) /= Magic or else Wire (9 .. 24) = Zero_Identity
        or else MC_Codec.U64 (Wire, 25) not in 1 .. Wide (Limit)
        or else MC_Codec.U64 (Wire, 33) not in 1 .. Wide (Limit)
        or else MC_Codec.U64 (Wire, 41) not in 1 .. Wide (Limit)
        or else MC_Codec.U64 (Wire, 49) > Wide (Pkg_Supply_Map.Max_Authorities) then return; end if;
      Result.Root_ID := Wire (9 .. 24); Result.Serial := Counter (MC_Codec.U64 (Wire, 25));
      Result.Not_Before := Counter (MC_Codec.U64 (Wire, 33)); Result.Expires := Counter (MC_Codec.U64 (Wire, 41));
      Result.Count := Natural (MC_Codec.U64 (Wire, 49));
      if Result.Not_Before >= Result.Expires or else Wire'Length /= Header_Size + Entry_Size * Result.Count then return; end if;
      for I in 1 .. Result.Count loop
         if Wire (Pos + 1 .. Pos + 32) = Zero_Digest or else Is_Zero (Wire (Pos + 33 .. Pos + 64))
           or else MC_Codec.U64 (Wire, Pos + 65) not in 1 .. Wide (Limit)
           or else MC_Codec.U64 (Wire, Pos + 73) not in 1 .. Wide (Pkg_Archive_Supply.Max_Lifetime) then return; end if;
         Result.Trusted (I) := (Wire (Pos + 1 .. Pos + 32), Wire (Pos + 33 .. Pos + 64),
            Counter (MC_Codec.U64 (Wire, Pos + 65)), Counter (MC_Codec.U64 (Wire, Pos + 73)));
         if I > 1 and then Result.Trusted (I - 1).Scope >= Result.Trusted (I).Scope then return; end if;
         Pos := Pos + Entry_Size;
      end loop;
      Value := Result; Status := OK;
   end Decode;
   procedure Decode_Floor (Wire : Bytes; Value : out Floor; Status : out Outcome) is
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Wire'First /= 1 or else Wire'Length /= Floor_Size or else Wire (1 .. 8) /= Floor_Magic
        or else Wire (9 .. 24) = Zero_Identity or else Wire (41 .. 72) = Zero_Digest
        or else MC_Codec.U64 (Wire, 25) not in 1 .. Wide (Limit)
        or else MC_Codec.U64 (Wire, 33) not in 1 .. Wide (Limit) then return; end if;
      Value := (Wire (9 .. 24), Counter (MC_Codec.U64 (Wire, 25)),
                Counter (MC_Codec.U64 (Wire, 33)), Wire (41 .. 72)); Status := OK;
   end Decode_Floor;
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      Status := Invalid_Input; if Deadline in 0 | Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Tick;
   procedure Protected_Root (Path : String; Directory : in out MC_FS.Root; Status : out Outcome) is
      Parent : MC_FS.Root; Info : MC_FS.Entry_Info;
   begin
      -- Check every ancestor, not only the final directory. The FS reader also
      -- forbids symlinks and magic links across the complete absolute path.
      MC_FS.Open_Root (Path, Directory, Status); if Status /= OK then return; end if;
      MC_FS.Root_Info (Directory, Info, Status);
      if Status = OK and then Info.UID /= 0 then Status := Denied; end if;
      if Status /= OK then MC_FS.Close (Directory); return; end if;
      for I in Path'Range loop
         if Path (I) = '/' then
            MC_FS.Open_Root ((if I = Path'First then "/" else Path (Path'First .. I - 1)), Parent, Status);
            if Status = OK then MC_FS.Root_Info (Parent, Info, Status); end if;
            MC_FS.Close (Parent);
            if Status = OK and then Info.UID /= 0 then Status := Denied; end if;
            if Status /= OK then MC_FS.Close (Directory); return; end if;
         end if;
      end loop;
   exception when others => MC_FS.Close (Parent); MC_FS.Close (Directory); Status := Indeterminate;
   end Protected_Root;
   procedure Read_Protected (Directory : MC_FS.Root; Name : String; Wire : out Bytes;
      Used : out Natural; Info : out MC_FS.Entry_Info; Status : out Outcome) is
      File : MC_FS.File; After : MC_FS.Entry_Info;
   begin
      Used := 0; Wire := (others => 0); Info := (others => <>);
      MC_FS.Open_Read (Directory, Name, File, Status);
      if Status = OK then MC_FS.Info (File, Info, Status); end if;
      if Status = OK and then (Info.Kind /= MC_FS.Regular or else Info.UID /= 0 or else Info.Links /= 1
        or else Info.Mode not in 8#440# | 8#640# | 8#444# | 8#644#
        or else Info.Size = 0 or else Info.Size > Counter (Wire'Length)) then Status := Denied; end if;
      if Status = OK then MC_FS.Read_At (File, 0, Wire, Used, Status); end if;
      if Status = OK and then Counter (Used) /= Info.Size then Status := Corrupt; end if;
      if Status = OK then MC_FS.Info (File, After, Status); end if;
      if Status = OK and then After /= Info then Status := Conflict; end if;
      MC_FS.Close (File);
      if Status /= OK then Used := 0; Wire := (others => 0); end if;
   exception when others => MC_FS.Close (File); Used := 0; Wire := (others => 0); Status := Indeterminate;
   end Read_Protected;
   procedure Close (Context : in out Session) is
   begin Context.Data := (others => <>); end Close;
   procedure Read_Current (Context : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Retained_Policy : Digest; Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome) is
      S : State renames Context.Data;
      Directory, Floors : MC_FS.Root; Policy_Info, Floor_Info, After : MC_FS.Entry_Info;
      Wire : Bytes (1 .. Maximum_Size); Anchor : Bytes (1 .. Floor_Size); Used : Natural;
      P : Policy; F : Floor; PH, FH : Digest;
      Started_UTC, Now : Counter;
      procedure Check is
      begin
         Status := Denied;
         if MC_Posix.Euid = 0 or else not S.Active or else Root_ID /= S.Root_ID
           or else Transaction_ID /= S.Transaction_ID or else Plan /= S.Plan or else Retained_Policy /= S.Retained_Policy then return; end if;
         Tick (S.Deadline, Status); if Status /= OK then return; end if;
         MC_Clock.Realtime_Seconds (Started_UTC, Status); if Status /= OK then return; end if;
         if Started_UTC < S.Last_UTC then Status := Stale; return; end if;
         Protected_Root (MC_Text.Image (S.Policy_Path), Directory, Status); if Status /= OK then return; end if;
         Protected_Root (MC_Text.Image (S.Floor_Path), Floors, Status); if Status /= OK then return; end if;
         Read_Protected (Floors, "supply.floor", Anchor, Used, Floor_Info, Status); if Status /= OK then return; end if;
         Decode_Floor (Anchor (1 .. Used), F, Status); if Status /= OK then return; end if;
         FH := MC_SHA256.Hash (Anchor);
         Read_Protected (Directory, "supply.bin", Wire, Used, Policy_Info, Status); if Status /= OK then return; end if;
         Decode (Wire (1 .. Used), P, Status); if Status /= OK then return; end if;
         PH := MC_SHA256.Hash (Wire (1 .. Used));
         Status := Denied;
         if P.Root_ID /= Root_ID or else F.Root_ID /= Root_ID or else P.Serial < F.Minimum_Serial
           or else PH /= F.Policy_Hash or else (S.Policy_Hash /= Zero_Digest and then S.Policy_Hash /= PH)
           or else (S.Floor_Hash /= Zero_Digest and then S.Floor_Hash /= FH) then return; end if;
         -- Reobserve the names after both reads, including an atomic replacement.
         MC_FS.Stat (Directory, "supply.bin", After, Status); if Status /= OK then return; end if;
         if After /= Policy_Info then Status := Conflict; return; end if;
         MC_FS.Stat (Floors, "supply.floor", After, Status); if Status /= OK then return; end if;
         if After /= Floor_Info then Status := Conflict; return; end if;
         MC_Clock.Realtime_Seconds (Now, Status); if Status /= OK then return; end if;
         if Now not in 1 .. Limit or else Now < Started_UTC or else Started_UTC < F.Minimum_UTC
           or else Started_UTC < P.Not_Before or else Now >= P.Expires then Status := Stale; return; end if;
         Tick (S.Deadline, Status); if Status /= OK then return; end if;
         S.Policy_Hash := PH; S.Floor_Hash := FH; S.Last_UTC := Now;
         Value := (Map => S.Map, Observed_At => Now, Count => P.Count, Trusted => P.Trusted);
      end Check;
   begin
      Value := (others => <>); Check;
      MC_FS.Close (Directory); MC_FS.Close (Floors);
      if Status /= OK then Close (Context); Value := (others => <>); end if;
   exception when others =>
      MC_FS.Close (Directory); MC_FS.Close (Floors); Close (Context);
      Value := (others => <>); Status := Indeterminate;
   end Read_Current;
   procedure Observe_Inputs (Context : in out Session;
      Policy_Hash, Floor_Hash : out Digest; Observed_At : out Counter; Status : out Outcome) is
      Value : Pkg_Supply_Policy.Snapshot;
      Root_ID : constant Identity := Context.Data.Root_ID;
      Transaction_ID : constant Identity := Context.Data.Transaction_ID;
      Plan : constant Digest := Context.Data.Plan;
      Retained_Policy : constant Digest := Context.Data.Retained_Policy;
   begin
      Policy_Hash := Zero_Digest; Floor_Hash := Zero_Digest; Observed_At := 0;
      Read_Current (Context, Root_ID, Transaction_ID, Plan, Retained_Policy, Value, Status);
      if Status = OK then
         Policy_Hash := Context.Data.Policy_Hash; Floor_Hash := Context.Data.Floor_Hash;
         Observed_At := Value.Observed_At;
      end if;
   end Observe_Inputs;
   procedure Observe (Context : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Retained_Policy : Digest; Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome) is
   begin
      if Context.Data.Planning then
         Close (Context); Value := (others => <>); Status := Denied; return;
      end if;
      Read_Current (Context, Root_ID, Transaction_ID, Plan, Retained_Policy, Value, Status);
   end Observe;
   procedure Observe_Planning (Context : in out Session; Root_ID, Transaction_ID : Identity;
      Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome) is
   begin
      if not Context.Data.Planning then
         Close (Context); Value := (others => <>); Status := Denied; return;
      end if;
      Read_Current (Context, Root_ID, Transaction_ID, Zero_Digest, Zero_Digest, Value, Status);
   end Observe_Planning;
   procedure Open_Planning (Policy_Directory, Floor_Directory : String;
      Root_ID, Transaction_ID : Identity; Deadline : Counter;
      Context : in out Session; Status : out Outcome) is
      Value : Pkg_Supply_Policy.Snapshot;
   begin
      Status := Conflict; if Context.Data.Active then return; end if;
      Close (Context); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Transaction_ID = Zero_Identity then return; end if;
      Tick (Deadline, Status); if Status /= OK then return; end if;
      MC_Text.Set (Context.Data.Policy_Path, Policy_Directory, Status); if Status /= OK then return; end if;
      MC_Text.Set (Context.Data.Floor_Path, Floor_Directory, Status); if Status /= OK then Close (Context); return; end if;
      Context.Data.Root_ID := Root_ID; Context.Data.Transaction_ID := Transaction_ID;
      Context.Data.Deadline := Deadline; Context.Data.Active := True; Context.Data.Planning := True;
      Observe_Planning (Context, Root_ID, Transaction_ID, Value, Status);
   end Open_Planning;
   procedure Bind_Publication (Context : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Retained_Policy, Map : Digest; Status : out Outcome) is
      Value : Pkg_Supply_Policy.Snapshot;
   begin
      Status := Invalid_Input;
      if Plan = Zero_Digest or else Retained_Policy = Zero_Digest or else Map = Zero_Digest then
         Close (Context); return;
      end if;
      Observe_Planning (Context, Root_ID, Transaction_ID, Value, Status); if Status /= OK then return; end if;
      Context.Data.Plan := Plan; Context.Data.Retained_Policy := Retained_Policy; Context.Data.Map := Map;
      Context.Data.Planning := False;
      Observe (Context, Root_ID, Transaction_ID, Plan, Retained_Policy, Value, Status);
   end Bind_Publication;
   procedure Open (Policy_Directory, Floor_Directory : String;
      Root_ID, Transaction_ID : Identity; Plan, Retained_Policy, Map : Digest;
      Deadline : Counter; Context : in out Session; Status : out Outcome) is
      Value : Pkg_Supply_Policy.Snapshot;
   begin
      Status := Conflict; if Context.Data.Active then return; end if;
      Close (Context); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Transaction_ID = Zero_Identity or else Plan = Zero_Digest
        or else Retained_Policy = Zero_Digest or else Map = Zero_Digest then return; end if;
      Tick (Deadline, Status); if Status /= OK then return; end if;
      MC_Text.Set (Context.Data.Policy_Path, Policy_Directory, Status); if Status /= OK then return; end if;
      MC_Text.Set (Context.Data.Floor_Path, Floor_Directory, Status); if Status /= OK then Close (Context); return; end if;
      Context.Data.Root_ID := Root_ID; Context.Data.Transaction_ID := Transaction_ID;
      Context.Data.Plan := Plan; Context.Data.Retained_Policy := Retained_Policy; Context.Data.Map := Map;
      Context.Data.Deadline := Deadline; Context.Data.Active := True;
      Observe (Context, Root_ID, Transaction_ID, Plan, Retained_Policy, Value, Status);
   end Open;
   procedure Observe_Current (Root_ID, Transaction_ID : Identity; Plan, Retained_Policy : Digest;
      Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome) is
   begin Observe (Context, Root_ID, Transaction_ID, Plan, Retained_Policy, Value, Status); end Observe_Current;
end Pkg_Site_Supply;
