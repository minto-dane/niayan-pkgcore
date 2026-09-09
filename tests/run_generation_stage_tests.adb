-- SPDX-License-Identifier: MIT
-- Synthetic artifacts and test-only authorization; never a production adapter.
with Ada.Command_Line; with Ada.Directories; with Interfaces.C;
with MC_Clock; with MC_Atomic; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Log_Format;
with MC_SHA256; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_File_Plan; with Pkg_Generation_Manifest; with Pkg_Generation_Stage; with Pkg_Root_State;
with Test_Support; use Test_Support;
procedure Run_Generation_Stage_Tests with SPARK_Mode => Off is
   package GM renames Pkg_Generation_Manifest;
   package FP renames Pkg_File_Plan;
   use type Interfaces.C.unsigned;
   use type Interfaces.C.int;
   use type GM.Manifest; use type MC_FS.Entry_Kind;
   M, Decoded, Bad : GM.Manifest;
   Manifest_Digest, Attrs, Payload, Catalog, Receipt, Ignored : Digest;
   Deadline : Counter := 0;
   S : Outcome; Store : MC_Store.Store; Root, State : MC_FS.Root; F : MC_FS.File;
   type Plan_Access is access FP.Plan;
   P, Q : constant Plan_Access := new FP.Plan;
   type Buffer_Access is access Bytes;
   Plan_Bytes : constant Buffer_Access := new Bytes (1 .. FP.Max_Plan_Bytes);
   Encoded : Bytes (1 .. GM.Max_Bytes); Used, Manifest_Used, Completed : Natural;
   Publish_Calls : Natural := 0; Stop_Publish : Natural := 0; Deny_Commit : Boolean := False;
   Deny_All : Boolean := False;
   procedure Authorize (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
   begin
      Status := Denied;
      if Deny_All or else Manifest /= Manifest_Digest or else Stage_ID /= M.Stage_ID
        or else Epoch /= M.Epoch or else Fence /= M.Fence then return; end if;
      if Plan = Zero_Digest then
         if Transaction_ID = M.Transaction_ID and then Evidence = Zero_Digest
           and then Phase in "stage:provision" | "stage:provision-root" | "stage:advance"
             | "stage:inspect" | "stage:inspect-batch" | "stage:inspected" then Status := OK; end if;
         return;
      end if;
      for I in 1 .. M.Count loop
         if Plan = M.Batches (I).Plan and then Transaction_ID = GM.Transaction (M, I)
           and then (Evidence = Zero_Digest or else Evidence = Receipt)
         then Status := OK; exit; end if;
      end loop;
      if Phase = "stage:publish-file" then
         Publish_Calls := Publish_Calls + 1;
         if Stop_Publish /= 0 and then Publish_Calls = Stop_Publish then Status := Denied; end if;
      elsif Phase = "stage:commit" and then (Deny_Commit or else Evidence /= Receipt) then Status := Denied;
      end if;
   end Authorize;
   package Stage is new Pkg_Generation_Stage (Authorize);
   Hold : Stage.Verified_Generation;
   procedure Need (Label_Text : String) is
   begin Expect (S = OK, Label_Text & Outcome'Image (S)); end Need;
   function Number (N : Natural) return String is
      Text : String (1 .. 4) := (others => '0'); Value : Natural := N;
   begin
      for I in reverse Text'Range loop Text (I) := Character'Val (48 + Value mod 10); Value := Value / 10; end loop;
      return Text;
   end Number;
   procedure Set_Entry (C : out FP.Change; Path : String; Directory : Boolean; Content : Digest := Zero_Digest) is
   begin
      C := (others => <>); MC_Text.Set (C.Path, Path, S); Need ("fixture path");
      C.After := (Node_Kind => (if Directory then FP.Directory else FP.Regular),
         Mode => (if Directory then 8#755# elsif Path = "catalog" then 8#400# else 8#644#),
         UID => Word (MC_Posix.Euid), GID => Word (MC_Posix.Egid),
         Content => Content, Xattrs => Attrs, Size => (if Directory then 0 else 3), others => <>);
   end Set_Entry;
   procedure Save (Plan : FP.Plan; D : out Digest) is
   begin FP.Encode (Plan, Plan_Bytes.all, Used, S); Need ("encode batch");
      MC_Store.Put (Store, Plan_Bytes (1 .. Used), D, S); Need ("store batch"); end Save;
   procedure Next is
   begin Stage.Advance (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
      Ada.Command_Line.Argument (3), Manifest_Digest, Completed, Deadline, S); end Next;
   procedure Inspect is
   begin Stage.Inspect (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
      Ada.Command_Line.Argument (3), Manifest_Digest, Deadline, S); end Inspect;
   procedure Commit_Window (Published : Boolean) is
      RS : Pkg_Root_State.State; Frame : Pkg_Root_State.Frame; N : Natural;
      Last_Frame : MC_Log_Format.Frame;
      Last : MC_Log_Format.Log_Entry;
      Name : constant String := "tx-" & MC_Hex.Encode (GM.Transaction (M, 2)) & ".log";
   begin
      -- Construct the exact durable prefix in THIS disposable fixture. This is
      -- restart testing, not evidence of actual hardware power-loss behavior.
      MC_Atomic.Read (State, "root.state", Frame, N, S); Need ("fixture state before cut");
      Pkg_Root_State.Decode (Frame, RS, S); Need ("decode fixture state");
      MC_Atomic.Read (State, Name, Plan_Bytes.all, N, S); Need ("fixture journal before cut");
      Last_Frame := Plan_Bytes (N - 255 .. N);
      MC_Log_Format.Decode (Last_Frame, Last, S); Need ("last fixture record");
      Expect (Last.Kind = 6, "cut immediately before committed record");
      RS.Active_Transaction := GM.Transaction (M, 2); RS.Active_Plan := M.Batches (2).Plan;
      if not Published then RS.Generation := 1; RS.Accepted_Plan := M.Batches (1).Plan; end if;
      MC_Atomic.Write (State, "root.state", Pkg_Root_State.Encode (RS), False, S); Need ("fixture commit-window state");
      MC_Atomic.Write (State, Name, Plan_Bytes (1 .. N - 256), False, S); Need ("fixture commit-window prefix");
      Next; Need ("reconcile recorded commit window"); Expect (Completed = 2, "commit window does not add a generation");
      Inspect; Need ("commit window full inspection");
   end Commit_Window;
begin
   Expect (Ada.Command_Line.Argument_Count = 3, "fresh private directories required");
   MC_Runtime.Initialize (S); Need ("runtime");
   MC_Clock.Boottime_Milliseconds (Deadline, S); Need ("stage clock"); Deadline := Deadline + 600_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (3), Store, S); Need ("store");
   MC_Store.Put (Store, Bytes'(0, 0), Attrs, S); Need ("attributes");
   MC_Store.Put (Store, Bytes'(97, 98, 99), Payload, S); Need ("payload");
   MC_Store.Put (Store, Bytes'(123, 125, 10), Catalog, S); Need ("opaque fixture catalog");
   MC_Store.Put (Store, Bytes'(1, 2, 3, 4), Receipt, S); Need ("fixture receipt");
   M.Stage_ID := (others => 41); M.Transaction_ID := (others => 42);
   M.Epoch := 1; M.Fence := 2; M.Catalog := Catalog; M.Effect_Contract := (others => 43);
   M.Count := 2; M.Entries := 1_054;
   Expect (MC_Hex.Encode (GM.Transaction (M, 1)) = "7c6717164cff85b29143ef40ee23f35f",
           "transaction binding matches independent SHA-256 big-endian vector");
   P.Root_ID := M.Stage_ID; P.Transaction_ID := GM.Transaction (M, 1);
   P.Target_Generation := 1; P.Epoch := M.Epoch; P.Fence := M.Fence;
   P.Package_Set := Catalog; P.Effect_Contract := M.Effect_Contract; P.Count := 1_024;
   Set_Entry (P.Changes (1), "catalog", False, Catalog);
   Set_Entry (P.Changes (2), "tree", True);
   Set_Entry (P.Changes (3), "tree/usr", True);
   Set_Entry (P.Changes (4), "tree/usr/bin", True);
   for I in 1 .. 1_020 loop Set_Entry (P.Changes (I + 4), "tree/usr/bin/file" & Number (I), False, Payload); end loop;
   Save (P.all, M.Batches (1).Plan); M.Batches (1).Receipt := Receipt;
   Q.all := P.all; Q.Transaction_ID := GM.Transaction (M, 2); Q.Base_Generation := 1; Q.Target_Generation := 2; Q.Count := 30;
   for I in 1 .. Q.Count loop Set_Entry (Q.Changes (I), "tree/usr/bin/file" & Number (I + 1_020), False, Payload); end loop;
   Save (Q.all, M.Batches (2).Plan); M.Batches (2).Receipt := Receipt;
   GM.Check (Store, M, S); Need ("complete cross-batch manifest");
   Bad := M; Bad.Entries := Bad.Entries - 1; GM.Check (Store, Bad, S); Expect (S = Conflict, "count mismatch refused");
   Bad := M; Bad.Catalog := Payload; GM.Check (Store, Bad, S); Expect (S = Conflict, "catalog binding refused");
   Bad := M; Bad.Batches (2).Plan := Bad.Batches (1).Plan; Expect (not GM.Valid (Bad), "duplicate batch refused");
   Q.Changes (1).Path := P.Changes (5).Path; Bad := M;
   Save (Q.all, Bad.Batches (2).Plan); GM.Check (Store, Bad, S); Expect (S = Conflict, "duplicate across batches refused");
   Set_Entry (Q.Changes (1), "tree/usr/missing/file", False, Payload); Q.Count := 1; Bad := M; Bad.Entries := 1_025;
   Save (Q.all, Bad.Batches (2).Plan); GM.Check (Store, Bad, S); Expect (S = Conflict, "missing cross-batch parent refused");
   Set_Entry (Q.Changes (1), "tree/var/lib/nia/file", False, Payload);
   Save (Q.all, Bad.Batches (2).Plan); GM.Check (Store, Bad, S); Expect (S = Denied, "wrapper does not bypass trust path exclusion");
   Q.Transaction_ID := (others => 99); Save (Q.all, Bad.Batches (2).Plan);
   GM.Check (Store, Bad, S); Expect (S = Conflict, "foreign transaction refused");
   Q.Transaction_ID := GM.Transaction (M, 2);
   Set_Entry (Q.Changes (1), "tree/usr/bin/link", False, Payload);
   Q.Changes (1).After.Node_Kind := FP.Symbolic_Link; Q.Changes (1).After.Mode := 8#777#;
   MC_Store.Put (Store, Bytes'(46, 46, 47, 46, 46, 47, 46, 46), Ignored, S); Need ("escaping link fixture");
   Q.Changes (1).After.Content := Ignored; Q.Changes (1).After.Size := 8;
   Save (Q.all, Bad.Batches (2).Plan); GM.Check (Store, Bad, S); Expect (S = Denied, "link cannot escape logical tree");
   GM.Encode (M, Encoded, Manifest_Used, S); Need ("encode manifest");
   Expect (MC_Hex.Encode (Encoded (121 .. 128)) = "0000041e00000002", "big-endian entry and batch counts");
   GM.Decode (Encoded (1 .. Manifest_Used), Decoded, S); Need ("decode manifest");
   Expect (Decoded = M, "canonical manifest round trip");
   Encoded (129) := 1; GM.Decode (Encoded (1 .. Manifest_Used), Bad, S); Expect (S = Invalid_Input, "reserved bytes refused"); Encoded (129) := 0;
   GM.Decode (Encoded (1 .. Manifest_Used - 1), Bad, S); Expect (S = Invalid_Input, "truncated manifest refused");
   GM.Decode (Encoded (1 .. Manifest_Used + 1), Bad, S); Expect (S = Invalid_Input, "trailing manifest bytes refused");
   declare Wire, Damaged : Bytes (1 .. GM.Max_Bytes); Size : Natural; Native, Readback : GM.Manifest; begin
      Native := M; Native.Format := GM.Native_V2;
      Expect (not GM.Valid (Native), "native format requires a retention root");
      Native.Catalog_Closure := (others => 91);
      GM.Encode (Native, Wire, Size, S); Need ("encode versioned retention binding");
      Expect (Wire (1 .. 8) = Bytes'(78, 73, 65, 71, 69, 78, 48, 50)
         and then Wire (129 .. 160) = Native.Catalog_Closure, "native header fields exact");
      GM.Decode (Wire (1 .. Size), Readback, S); Need ("decode native header");
      Expect (Readback = Native, "full native record round trip");
      Expect (MC_Hex.Encode (GM.Transaction (Native, 1)) = "3db3acbcc26837f41a20e193447182bb", "native transaction matches independent versioned vector");
      Damaged := Wire; Damaged (8) := 49; GM.Decode (Damaged (1 .. Size), Readback, S);
      Expect (S = Invalid_Input and then Readback = GM.Manifest'(others => <>), "native header cannot be relabeled as v1");
      Damaged := Wire; Damaged (129 .. 160) := Zero_Digest; GM.Decode (Damaged (1 .. Size), Readback, S);
      Expect (S = Invalid_Input and then Readback = GM.Manifest'(others => <>), "missing closure clears decoded output");
      Damaged := Wire; Damaged (8) := 51; GM.Decode (Damaged (1 .. Size), Readback, S);
      Expect (S = Unsupported and then Readback = GM.Manifest'(others => <>), "unknown profile cannot downgrade");
      Native.Format := GM.Structural_V1; Expect (not GM.Valid (Native), "v1 must keep reserved bytes zero");
      GM.Check_Retention (Store, M, Deadline, S); Expect (S = Unsupported, "v1 is not native retention evidence");
      Native.Format := GM.Native_V2; GM.Check_Retention (Store, Native, Counter'Last, S);
      Expect (S = Invalid_Input, "unbounded retention deadline refused");
   end;
   Manifest_Digest := MC_SHA256.Hash (Encoded (1 .. Manifest_Used)); MC_Store.Close (Store);
   if MC_Posix.Euid = 0 then
      Stage.Provision (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Ada.Command_Line.Argument (3),
         Encoded (1 .. Manifest_Used), Manifest_Digest, Deadline, S); Expect (S = Denied, "root provision refused for valid fixture");
      Next; Expect (S = Denied, "root advance refused"); Inspect; Expect (S = Denied, "root inspection refused");
      Stage.Verify_And_Hold (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
         Ada.Command_Line.Argument (3), Manifest_Digest, Hold, Deadline, S);
      Expect (S = Denied and then not Stage.Held (Hold), "root held inspection refused");
      Report; return;
   end if;
   Deny_All := True;
   Stage.Provision (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Ada.Command_Line.Argument (3),
      Encoded (1 .. Manifest_Used), Manifest_Digest, Deadline, S); Expect (S = Denied, "unauthorized provision refused");
   Deny_All := False;
   Stage.Provision (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Ada.Command_Line.Argument (3),
      Encoded (1 .. Manifest_Used), (others => 9), Deadline, S); Expect (S = Denied, "wrong manifest digest refused");
   Stage.Provision (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Ada.Command_Line.Argument (3),
      Encoded (1 .. Manifest_Used), Manifest_Digest, Deadline, S); Need ("provision stage");
   Stage.Provision (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Ada.Command_Line.Argument (3),
      Encoded (1 .. Manifest_Used), Manifest_Digest, Deadline, S); Expect (S = Conflict, "no rebootstrap of existing generation");
   Inspect; Expect (S = Conflict, "unfinished generation never accepted");
   declare
      Name : aliased Interfaces.C.char_array := Interfaces.C.To_C (Ada.Command_Line.Argument (1));
      FD : MC_Posix.FD := MC_Posix.Open (Name'Address, MC_Posix.O_RDONLY + MC_Posix.O_DIRECTORY + MC_Posix.O_NOFOLLOW, 0);
   begin
      Expect (FD >= 0, "open private fixture directory");
      Expect (MC_Posix.Fchmod (FD, 8#755#) = 0, "fixture becomes non-private");
      Next; Expect (S = Denied, "non-private generation refused before advance");
      Expect (MC_Posix.Fchmod (FD, 8#700#) = 0, "restore private fixture");
      Expect (MC_Posix.Close (FD) = 0, "close private fixture descriptor"); FD := -1;
   end;
   Stop_Publish := 6; Next; Expect (S = Denied and then Completed = 0, "interrupted first batch retained");
   Stop_Publish := 0; Next; Need ("resume partially materialized batch"); Expect (Completed = 1, "one private batch committed");
   Inspect; Expect (S = Conflict, "first batch not a complete generation");
   Deny_Commit := True; Next; Expect (S = Denied and then Completed = 0, "commit revocation preserved");
   Deny_Commit := False; Next; Need ("resume applied second batch"); Expect (Completed = 2, "second private batch committed");
   Next; Need ("idempotent completed stage"); Expect (Completed = 2, "no extra generation on repeat");
   Inspect; Need ("all 1054 entries verified including 1050 children of one directory");
   Stage.Verify_And_Hold (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
      Ada.Command_Line.Argument (3), Manifest_Digest, Hold, Deadline, S); Need ("hold verified generation");
   Expect (Stage.Held (Hold) and then Stage.Manifest (Hold) = Manifest_Digest, "held manifest binding");
   Next; Expect (S /= OK, "held verification excludes stage writer");
   Inspect; Expect (S /= OK, "held verification excludes second inspection");
   MC_FS.Open_Root (Ada.Command_Line.Argument (2), State, S, Private_Only => True); Need ("held state fixture");
   MC_FS.Open_Locked (State, "root.lock", F, S, Create_If_Missing => False);
   Expect (S /= OK, "held verification excludes lower-level file writer"); MC_FS.Close (F); MC_FS.Close (State);
   MC_Store.Open (Ada.Command_Line.Argument (3), Store, S); Need ("publication can reacquire CAS while stage is held");
   MC_Store.Close (Store);
   Stage.Verify_And_Hold (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2),
      Ada.Command_Line.Argument (3), Manifest_Digest, Hold, Deadline, S);
   Expect (S = Conflict and then Stage.Held (Hold), "cannot overwrite a held reservation");
   Stage.Close (Hold); Stage.Close (Hold);
   Expect (not Stage.Held (Hold) and then Stage.Manifest (Hold) = Zero_Digest, "close releases and clears reservation");
   Inspect; Need ("inspection succeeds after release");
   Deny_All := True; Inspect; Expect (S = Denied, "inspection requires live reservation"); Deny_All := False;
   MC_FS.Open_Root (Ada.Command_Line.Argument (1), Root, S, Private_Only => True); Need ("fixture root");
   MC_Atomic.Write (Root, "tree/usr/bin/untracked", Bytes'(1 => 9), True, S); Need ("extra fixture entry");
   Inspect; Expect (S = Conflict, "untracked entry refused without unbounded name list");
   MC_FS.Remove (Root, "tree/usr/bin/untracked", False, S); Need ("remove extra fixture");
   declare Info : MC_FS.Entry_Info;
      Original : constant String := Ada.Command_Line.Argument (1) & "/tree/usr/bin/file0001";
      Retained : constant String := Ada.Command_Line.Argument (2) & "/retained-payload";
   begin
      MC_FS.Stat (Root, "tree/usr/bin/file0001", Info, S); Need ("original fixture attributes");
      Ada.Directories.Rename (Original, Retained);
      MC_FS.Create_New (Root, "tree/usr/bin/file0001", F, S); Need ("changed fixture file");
      MC_FS.Write_All (F, Bytes'(120, 121, 122), S); Need ("changed fixture bytes");
      MC_FS.Set_Metadata (F, Info, S); Need ("same mode owner size timestamp"); MC_FS.Close (F);
      Inspect; Expect (S = Conflict, "changed payload refused with same count and attributes");
      MC_FS.Remove (Root, "tree/usr/bin/file0001", False, S); Need ("remove changed fixture");
      Ada.Directories.Rename (Retained, Original);
   end;
   MC_FS.Open_Root (Ada.Command_Line.Argument (2), State, S, Private_Only => True); Need ("fixture state");
   MC_FS.Open_Locked (State, "generation.lock", F, S, Create_If_Missing => False); Need ("hold reservation fixture");
   Next; Expect (S /= OK, "concurrent stage writer refused"); Inspect; Expect (S /= OK, "inspection cannot race writer"); MC_FS.Close (F);
   MC_FS.Rename (State, "generation.lock", "retained-lock", True, S); Need ("retain fixture lock");
   Next; Expect (S = Corrupt, "missing lock not recreated");
   declare Info : MC_FS.Entry_Info; begin
      MC_FS.Stat (State, "generation.lock", Info, S); Need ("observe missing lock"); Expect (Info.Kind = MC_FS.Absent, "no replacement lock");
   end;
   MC_FS.Rename (State, "retained-lock", "generation.lock", True, S); Need ("restore fixture lock");
   Commit_Window (False); Commit_Window (True);
   declare Name : constant String := "tx-" & MC_Hex.Encode (GM.Transaction (M, 1)) & ".log"; begin
      MC_FS.Rename (State, Name, "retained-journal", True, S); Need ("retain first journal");
      Inspect; Expect (S = Corrupt, "missing old batch journal refused");
      MC_FS.Rename (State, "retained-journal", Name, True, S); Need ("restore exact first journal");
      MC_Atomic.Read (State, Name, Plan_Bytes.all, Used, S); Need ("retain exact journal bytes");
      MC_FS.Open_Locked (State, Name, F, S, Create_If_Missing => False); Need ("open fixture journal for torn-tail injection");
      MC_FS.Append_Durable (F, Counter (Used), Bytes'(1 => 17), S); Need ("fixture torn tail"); MC_FS.Close (F);
      Inspect; Expect (S = Indeterminate, "partial old journal is not repaired automatically");
      declare Info : MC_FS.Entry_Info; begin
         MC_FS.Stat (State, Name, Info, S); Need ("observe retained tail");
         Expect (Info.Size = Counter (Used + 1), "partial bytes preserved");
      end;
      MC_Atomic.Write (State, Name, Plan_Bytes (1 .. Used), False, S); Need ("restore exact fixture journal bytes");
   end;
   MC_Store.Open (Ada.Command_Line.Argument (3), Store, S); Need ("open final store");
   MC_Store.Check_Pin (Store, M.Transaction_ID, Manifest_Digest, S); Need ("manifest remains pinned");
   MC_Store.Put (Store, Bytes'(1 => 5), Ignored, S); Need ("unreferenced CAS object allowed"); MC_Store.Close (Store);
   Inspect; Need ("restored fixture fully reverified");
   MC_FS.Close (Root); MC_FS.Close (State); Report;
exception when others => Stage.Close (Hold); MC_Store.Close (Store); MC_FS.Close (Root); MC_FS.Close (State); MC_FS.Close (F); raise;
end Run_Generation_Stage_Tests;
