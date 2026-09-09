-- SPDX-License-Identifier: MIT
-- Disposable synthetic generations and test-only authorities. These fixtures
-- exercise the real composed guard; they do not attest real native DEB effects,
-- a physical stop barrier, independent trust floors, or a running boot image.
with Ada.Command_Line; with Ada.Directories; with Ada.Unchecked_Deallocation;
with Interfaces.C; with System;
with MC_Atomic; with MC_Codec; with MC_Config_Auth; with MC_Config_Receipt;
with MC_Contract_Profile; with MC_FS; with MC_Hex; with MC_Log_Format; with MC_Posix;
with MC_Runtime; with MC_SHA256; with MC_Stop_Barrier; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_File_Plan; with Pkg_Generation_Descriptor; with Pkg_Generation_Manifest;
with Pkg_Generation_Publisher; with Pkg_Generation_Stage; with Pkg_Managed_Engine; with Pkg_Root_State;
with Resolver_Model; with Resolver_Admission; with Resolver_Wire;
with Test_Support; use Test_Support;
procedure Run_Generation_Publication_Tests with SPARK_Mode => Off is
   package GD renames Pkg_Generation_Descriptor; package GM renames Pkg_Generation_Manifest;
   package FP renames Pkg_File_Plan; package CR renames MC_Config_Receipt;
   package SB renames MC_Stop_Barrier; package RM renames Resolver_Model;
   use type Interfaces.C.int; use type Interfaces.C.unsigned;
   use type Interfaces.C.unsigned_long_long; use type Byte; use type GD.Descriptor;
   use type RM.Binding;
   Root_ID : constant Identity := (others => 31);
   Grant : constant Digest := (others => 32);
   Boot : constant Identity := (others => 33);
   Mark : constant Digest := (others => 34);
   Source : constant Digest := (others => 35);
   Reservation : constant Digest := (others => 36);
   S : Outcome; Store : MC_Store.Store; State, Root : MC_FS.Root;
   M : GM.Manifest; Manifest_Hash, Attrs, Catalog, Receipt, Plan_Hash, Ignored : Digest;
   Before, After, Current, Decoded, Other : GD.Descriptor;
   First_Plan : Digest; First_Tx : Identity;
   type Plan_Access is access FP.Plan;
   P, Batch : constant Plan_Access := new FP.Plan;
   type Buffer_Access is access Bytes;
   B : constant Buffer_Access := new Bytes (1 .. FP.Max_Plan_Bytes);
   type Universe_Access is access RM.Universe;
   U0 : constant Universe_Access := new RM.Universe;
   Universe_Hash : Digest;
   Used, Completed : Natural;
   Root_Path : constant String := Ada.Command_Line.Argument (1);
   State_Path : constant String := Ada.Command_Line.Argument (2);
   Store_Path : constant String := Ada.Command_Line.Argument (3);
   Bank : constant String := Ada.Command_Line.Argument (4);
   type Fault is (None, Authority_Denied, Barrier_Expired, Signature_Damaged,
      Configuration_Stale, Coverage_Missing, Admission_Stale, Native_Denied,
      Current_Changed, Commit_Denied, Stage_Denied, Bootstrap_Denied);
   Inject : Fault := None;
   Native_Calls, Recheck_Calls, Config_Calls : Natural := 0;
   Probed : Boolean := False;
   procedure Probe_Reservations;
   SK1, SK2 : Bytes (1 .. 64); PK1, PK2 : Digest;
   function Keypair (PK, SK, Seed : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_seed_keypair";
   function Sign (Signature, Length, Message : System.Address;
      Size : Interfaces.C.unsigned_long_long; SK : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_detached";
   procedure Need (Label_Text : String) is
   begin Expect (S = OK, Label_Text & Outcome'Image (S)); end Need;
   function Matches (R, T : Identity; H : Digest) return Boolean is
     (R = Root_ID and then T = P.Transaction_ID and then H = Plan_Hash);
   procedure Authorize (R, T : Identity; H, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
   begin
      Status := Denied;
      if Inject = Authority_Denied or else not Matches (R, T, H)
        or else Epoch /= 1 or else Fence /= 2
        or else (Evidence /= Zero_Digest and then Evidence /= Receipt)
        or else Phase not in "prepare" | "capture" | "apply" | "commit" |
          "file-effect" | "publish-file" | "finish-terminal" then return; end if;
      if Phase = "commit" and then (Inject = Commit_Denied or else Evidence /= Receipt) then return; end if;
      if not Probed and then Phase = "prepare" and then Inject = Commit_Denied then Probe_Reservations; end if;
      Status := OK;
   end Authorize;
   procedure Observe_Barrier (R, T : Identity; H : Digest;
      Policy : out SB.Policy; State : out SB.State; Now : out Counter;
      Receiver_Boot : out Identity; Status : out Outcome) is
   begin
      Policy := (Cluster_ID => Boot, Barrier_ID => (others => 37), Receiver_Boot => Boot,
         Contract => MC_Contract_Profile.Fingerprint, Change_Plan => Plan_Hash,
         Inventory => Mark, Guard_Value => Mark, Epoch => 1, Guard_Revision => 1,
         Maximum_Age => 120, Count => 1, others => <>);
      Policy.Members (1) := (Node_ID => Boot, Resource_ID => Root_ID, Boot_ID => Boot,
         Stop_Key => Mark, Fence_Key => Source, Required_Isolation_Paths => 1);
      -- Synthetic observed state, not a signature or physical fencing claim.
      SB.Initialize (Policy, State, Status);
      State.Current := SB.Sealed; State.Revision := 1; State.Last_Now := 100;
      State.Members (1) := (Current => SB.Acknowledged, Node_Sequence => 1,
         Observed => 90, Expires => 200, Proof => Mark, Audit_Head => Mark, others => <>);
      Now := (if Inject = Barrier_Expired then 200 else 100); Receiver_Boot := Boot;
      if not Matches (R, T, H) then Status := Denied; end if;
   end Observe_Barrier;
   function Scope (Phase : String) return CR.Phase is
     (if Phase = "commit" then CR.Accept_Running else CR.Before_Apply);
   procedure Sign_Role (Role : String; Wire : CR.Wire; SK : Bytes; Signature : out Bytes) is
      Message : Bytes (1 .. 2 + Role'Length + Wire'Length); Offset : Natural := 2;
      Length : aliased Interfaces.C.unsigned_long_long := 0;
   begin
      MC_Codec.Put16 (Message, 1, Role'Length);
      for C of Role loop Offset := Offset + 1; Message (Offset) := Byte (Character'Pos (C)); end loop;
      Message (Offset + 1 .. Message'Last) := Wire;
      Expect (Sign (Signature'Address, Length'Address, Message'Address, Message'Length, SK'Address) = 0
         and then Length = 64, "sign isolated test configuration role");
   end Sign_Role;
   procedure Observe_Configuration (R, T : Identity; H : Digest; Phase : String;
      Expected : out CR.Subject; A : out MC_Config_Auth.Authority;
      C : out MC_Config_Auth.Certificate; Now, Floor : out Counter; Status : out Outcome) is
      Receipt_Data : CR.Receipt; Wire : CR.Wire;
   begin
      Config_Calls := Config_Calls + 1;
      Expected := (Root => Root_ID, Transaction => P.Transaction_ID, Boot => Boot,
         Plan => Plan_Hash, Target_Set => Catalog, Contract => MC_Contract_Profile.Fingerprint,
         Effective_Config => Mark, Source_Inventory => Mark, Input_State => Mark,
         Generated_Set => Mark, Adapter_Set => Mark, Validator_Set => Mark,
         Policy => Mark, Report => Mark, Generation => After.Generation,
         Epoch => 1, Sequence => 1, Scope => Scope (Phase));
      Receipt_Data := (Binding => Expected, Observed_At => 90, Not_Before => 80, Expires => 200,
         Complete_Inputs => True, Native_Validated => True, Constraints_Passed => True,
         Derived_Current => True, Running_Exact => True, Rollback_Compatible => False);
      A := (Validator_Key => PK1, Reviewer_Key => PK2, Validator_Domain => Boot,
         Reviewer_Domain => (others => 38), Policy => Mark, Max_Age => 120, Max_Lifetime => 120);
      Now := 100; Floor := (if Inject = Configuration_Stale then 2 else 1); C := (others => 0);
      CR.Encode (Receipt_Data, Wire, Status); if Status /= OK then return; end if;
      C (1 .. 512) := Wire;
      Sign_Role ("MissionCore/config-approval/v1/validator", Wire, SK1, C (513 .. 576));
      Sign_Role ("MissionCore/config-approval/v1/reviewer", Wire, SK2, C (577 .. 640));
      if Inject = Signature_Damaged then C (577) := C (577) xor 1; end if;
      if not Matches (R, T, H) then Status := Denied; end if;
   end Observe_Configuration;
   procedure Observe_Resolution (R, T : Identity; H : Digest; Phase : String;
      U : out RM.Universe; Proposal : out RM.Proposal;
      A : out Resolver_Admission.Admission; Expected : out RM.Binding;
      Expected_Universe, Native_Source, Held_Reservation : out Digest;
      Now, Trust_Floor : out Counter; Status : out Outcome) is
   begin
      U := U0.all; Proposal := (others => <>); Proposal.Selected (1) := True;
      Proposal.Universe_Hash := Universe_Hash; Expected := U.Subject;
      Expected_Universe := Universe_Hash; Native_Source := Source; Held_Reservation := Reservation;
      Now := 100; Trust_Floor := (if Inject = Admission_Stale then 2 else 1);
      A := (Subject => U.Subject, Native_Source => Source, Universe_Hash => Universe_Hash,
         Physical_Plan => Plan_Hash, Reservation => Reservation, Expires => 200, Trust_Floor => 1,
         Count => 1, others => <>);
      A.Items (1) := (Artifact => U.Items (1).Object_Hash, Adapter => Mark, Source_Mark => Mark,
         Evidence => Mark, Observed => (others => Mark), Interpreted => (others => Mark), Unsupported_Count => 0);
      if Inject = Coverage_Missing then A.Items (1).Interpreted (Resolver_Admission.Side_Effects) := Zero_Digest; end if;
      Status := (if Matches (R, T, H) and then Phase'Length > 0 then OK else Denied);
   end Observe_Resolution;
   procedure Check_Native (U : RM.Universe; Proposal : RM.Proposal;
      Native_Source, Physical_Plan, Held_Reservation : Digest; Phase : String; Status : out Outcome) is
   begin
      Native_Calls := Native_Calls + 1;
      Status := (if Inject /= Native_Denied and then U.Subject = U0.Subject
        and then Proposal.Universe_Hash = Universe_Hash and then Native_Source = Source
        and then Physical_Plan = Plan_Hash and then Held_Reservation = Reservation
        and then Phase'Length > 0 then OK else Denied);
   end Check_Native;
   procedure Recheck (Expected : RM.Binding; Hash, Native_Source, Physical_Plan, Held_Reservation : Digest;
      Expires, Trust_Floor : Counter; Status : out Outcome) is
   begin
      Recheck_Calls := Recheck_Calls + 1;
      Status := (if Inject /= Current_Changed and then Expected = U0.Subject and then Hash = Universe_Hash
        and then Native_Source = Source and then Physical_Plan = Plan_Hash
        and then Held_Reservation = Reservation and then Expires = 200 and then Trust_Floor = 1 then OK else Denied);
   end Recheck;
   package Managed is new Pkg_Managed_Engine
      (Authorize, Observe_Barrier, Scope, Observe_Configuration, Observe_Resolution, Check_Native, Recheck);
   procedure Authorize_Stage (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
   begin
      Status := Denied;
      if Inject = Stage_Denied or else Manifest /= Manifest_Hash or else Stage_ID /= M.Stage_ID
        or else Epoch /= 1 or else Fence /= 2 then return; end if;
      if Plan = Zero_Digest and then Transaction_ID = M.Transaction_ID and then Evidence = Zero_Digest
        and then Phase in "stage:provision" | "stage:provision-root" | "stage:advance"
          | "stage:inspect" | "stage:inspect-batch" | "stage:inspected" then Status := OK;
      elsif Plan = M.Batches (1).Plan and then Transaction_ID = GM.Transaction (M, 1)
        and then (Evidence = Zero_Digest or else Evidence = Receipt)
        and then Phase in "stage:prepare" | "stage:capture" | "stage:apply" | "stage:commit"
          | "stage:file-effect" | "stage:publish-file" | "stage:finish-terminal" then Status := OK;
      end if;
   end Authorize_Stage;
   procedure Bootstrap (R : Identity; G : Digest; Status : out Outcome) is
   begin Status := (if Inject /= Bootstrap_Denied and then R = Root_ID and then G = Grant then OK else Denied); end Bootstrap;
   package Stage is new Pkg_Generation_Stage (Authorize_Stage);
   package Publisher is new Pkg_Generation_Publisher (Managed, Authorize_Stage, Bootstrap);
   procedure Probe_Reservations is
      Local : Outcome; D : GD.Descriptor; Count : Natural;
      Stage_State : MC_FS.Root; Lock : MC_FS.File;
      Path : constant String := GD.Stage_Path (Bank, After);
   begin
      Probed := True;
      Publisher.Read_Current (Root_Path, State_Path, Store_Path, Root_ID, D, Local);
      Expect (Local /= OK and then D = GD.Empty, "publisher holds reader reservation during managed gate");
      Stage.Advance (Path & "/root", Path & "/state", Store_Path, Manifest_Hash, Count, Local);
      Expect (Local /= OK, "publisher retains verified stage writer reservation");
      MC_FS.Open_Root (Path & "/state", Stage_State, Local, Private_Only => True);
      Expect (Local = OK, "open selected stage state during publication");
      MC_FS.Open_Locked (Stage_State, "root.lock", Lock, Local, Create_If_Missing => False);
      Expect (Local /= OK, "publisher retains verified stage lower-level reservation");
      MC_FS.Close (Lock); MC_FS.Close (Stage_State);
   exception when others => MC_FS.Close (Lock); MC_FS.Close (Stage_State); raise;
   end Probe_Reservations;
   procedure Publish is
   begin Publisher.Publish (Root_Path, State_Path, Store_Path, Bank, Plan_Hash, Receipt, S); end Publish;
   procedure Read_Current is
   begin Publisher.Read_Current (Root_Path, State_Path, Store_Path, Root_ID, Current, S); end Read_Current;
   procedure Save_Plan is
   begin FP.Encode (P.all, B.all, Used, S); Need ("encode publication plan");
      MC_Store.Put (Store, B (1 .. Used), Plan_Hash, S); Need ("store publication plan"); end Save_Plan;
   procedure Check_Plan_Restrictions is
      Original : constant Digest := Plan_Hash;
   begin
      MC_Store.Open (Store_Path, Store, S); Need ("open descriptor test CAS");
      Batch.all := P.all;
      GD.Check (Store, P.all, Other, Decoded, S); Need ("canonical publication plan accepted");
      Expect (Other = Before and then Decoded = After, "plan binds both descriptors");
      P.Count := 2; GD.Check (Store, P.all, Other, Decoded, S); Expect (S /= OK, "extra publication effect refused"); P.all := Batch.all;
      MC_Text.Set (P.Changes (1).Path, "other", S); Need ("alter publication path fixture");
      GD.Check (Store, P.all, Other, Decoded, S); Expect (S /= OK, "arbitrary publication path refused"); P.all := Batch.all;
      P.Package_Set := Mark; GD.Check (Store, P.all, Other, Decoded, S); Expect (S /= OK, "independent catalog substitution refused"); P.all := Batch.all;
      P.Changes (1).After.Mode := 8#600#; GD.Check (Store, P.all, Other, Decoded, S);
      Expect (S /= OK, "noncanonical descriptor shape refused"); P.all := Batch.all;
      P.Epoch := 2; Save_Plan; MC_Store.Close (Store);
      Publish; Expect (S = Denied, "stage and publication epochs must agree");
      Plan_Hash := Original; P.all := Batch.all;
      for Variant in 1 .. 2 loop
         Other := After;
         if Variant = 1 then Other.Catalog := Receipt; else Other.Stage_ID := (others => 77); end if;
         MC_Store.Open (Store_Path, Store, S); Need ("open substituted descriptor fixture CAS");
         MC_Store.Put (Store, GD.Encode (Other), Ignored, S); Need ("store substituted descriptor fixture");
         GD.Compile (Before, Other, Batch.Transaction_ID, 1, 2, Mark, Word (MC_Posix.Euid), Word (MC_Posix.Egid), P.all, S);
         Need ("structurally valid substituted descriptor"); Save_Plan; MC_Store.Close (Store);
         Publish; Expect (S = Conflict, "manifest rejects substituted catalog or stage identity");
         Plan_Hash := Original; P.all := Batch.all;
      end loop;
   end Check_Plan_Restrictions;
   procedure Build (N : Positive) is
      Wire : Bytes (1 .. GM.Max_Bytes); N_Bytes : Natural;
      type UB_Access is access Bytes;
      UB : UB_Access := new Bytes (1 .. Resolver_Wire.Maximum_Universe_Bytes);
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, UB_Access);
   begin
      MC_Store.Open (Store_Path, Store, S); Need ("open fixture CAS");
      MC_Store.Put (Store, Bytes'(123, Byte (N), 125), Catalog, S); Need ("synthetic catalog bytes");
      M := (Stage_ID => (others => Byte (40 + N)), Transaction_ID => (others => Byte (50 + N)),
         Epoch => 1, Fence => 2, Catalog => Catalog, Effect_Contract => Mark, Entries => 3, Count => 1, others => <>);
      FP.Clear (Batch.all); Batch.Root_ID := M.Stage_ID; Batch.Transaction_ID := GM.Transaction (M, 1);
      Batch.Target_Generation := 1; Batch.Epoch := 1; Batch.Fence := 2;
      Batch.Package_Set := Catalog; Batch.Effect_Contract := Mark; Batch.Count := 3;
      MC_Text.Set (Batch.Changes (1).Path, "catalog", S); Need ("fixture catalog path");
      Batch.Changes (1).After := (Node_Kind => FP.Regular, Mode => 8#400#,
         UID => Word (MC_Posix.Euid), GID => Word (MC_Posix.Egid), Size => 3,
         Content => Catalog, Xattrs => Attrs, others => <>);
      MC_Text.Set (Batch.Changes (2).Path, "tree", S); Need ("fixture tree path");
      Batch.Changes (2).After := (Node_Kind => FP.Directory, Mode => 8#755#,
         UID => Word (MC_Posix.Euid), GID => Word (MC_Posix.Egid), Xattrs => Attrs, others => <>);
      MC_Text.Set (Batch.Changes (3).Path, "tree/version", S); Need ("fixture payload path");
      Batch.Changes (3).After := Batch.Changes (1).After; Batch.Changes (3).After.Mode := 8#644#;
      FP.Encode (Batch.all, B.all, N_Bytes, S); Need ("encode private batch");
      MC_Store.Put (Store, B (1 .. N_Bytes), M.Batches (1).Plan, S); Need ("save private batch");
      M.Batches (1).Receipt := Receipt;
      GM.Encode (M, Wire, N_Bytes, S); Need ("encode stage fixture");
      MC_Store.Put (Store, Wire (1 .. N_Bytes), Manifest_Hash, S); Need ("stage manifest CAS");
      After := (Root_ID, M.Stage_ID, Manifest_Hash, Catalog, Counter (N),
         (if N = 1 then Zero_Digest else MC_SHA256.Hash (GD.Encode (Before))));
      MC_Store.Put (Store, GD.Encode (After), Ignored, S); Need ("descriptor CAS");
      GD.Compile (Before, After, (others => Byte (60 + N)), 1, 2, Mark,
         Word (MC_Posix.Euid), Word (MC_Posix.Egid), P.all, S); Need ("compile publication");
      Save_Plan; MC_Store.Close (Store);
      declare Path : constant String := GD.Stage_Path (Bank, After); begin
         Ada.Directories.Create_Directory (Path);
         Ada.Directories.Create_Directory (Path & "/root"); Ada.Directories.Create_Directory (Path & "/state");
         if MC_Posix.Euid /= 0 then
            Stage.Provision (Path & "/root", Path & "/state", Store_Path, Wire (1 .. N_Bytes), Manifest_Hash, S);
            Need ("provision selected stage");
         end if;
      end;
      U0.Subject := (Root => MC_SHA256.Hash (Root_ID), Boot => Mark, Snapshot => Catalog, Policy => Mark,
         Adapter_Set => Mark, Native_Inventory => Source, Configuration => Mark, Effect_Contracts => Mark, Generation => Counter (N));
      U0.Item_Count := 1; U0.Items (1) := (Object_Hash => Catalog, Metadata_Hash => Mark,
         Adapter_Hash => Mark, Initially_Present => True, Permitted => True, others => <>);
      Resolver_Wire.Encode (U0.all, UB.all, N_Bytes, S); Need ("encode closed synthetic universe");
      Universe_Hash := MC_SHA256.Hash (UB (1 .. N_Bytes)); Free (UB);
   end Build;
   procedure Complete_Stage is
      Path : constant String := GD.Stage_Path (Bank, After);
   begin Stage.Advance (Path & "/root", Path & "/state", Store_Path, Manifest_Hash, Completed, S);
      Need ("assemble selected stage"); Expect (Completed = 1, "single private batch complete"); end Complete_Stage;
   procedure Commit_Window (Published, Finished : Boolean) is
      RS : Pkg_Root_State.State; Frame : Pkg_Root_State.Frame; N : Natural;
      Last : MC_Log_Format.Log_Entry; Last_Frame : MC_Log_Format.Frame;
      Name : constant String := "tx-" & MC_Hex.Encode (P.Transaction_ID) & ".log";
   begin
      MC_Atomic.Read (State, "root.state", Frame, N, S); Need ("retain committed state");
      Pkg_Root_State.Decode (Frame, RS, S); Need ("decode committed state");
      MC_Atomic.Read (State, Name, B.all, N, S); Need ("retain committed journal");
      Last_Frame := B (N - 255 .. N); MC_Log_Format.Decode (Last_Frame, Last, S); Need ("decode last record");
      Expect (Last.Kind = 6, "fixture last record is committed");
      RS.Active_Transaction := P.Transaction_ID; RS.Active_Plan := Plan_Hash;
      if not Published then RS.Generation := Before.Generation; RS.Accepted_Plan := First_Plan; RS.Package_Set := Before.Catalog; end if;
      MC_Atomic.Write (State, "root.state", Pkg_Root_State.Encode (RS), False, S); Need ("inject durable commit window");
      if not Finished then MC_Atomic.Write (State, Name, B (1 .. N - 256), False, S); Need ("inject commit-intent prefix"); end if;
      Read_Current; Expect (S = Indeterminate and then Current = GD.Empty, "uncleared commit window never exposes a generation");
      Publish; Need ("recover durable commit window");
      Read_Current; Need ("read recovered commit"); Expect (Current = After, "recovery preserves one root/catalog decision");
   end Commit_Window;
begin
   Expect (Ada.Command_Line.Argument_Count = 4, "four disposable private directories required");
   MC_Runtime.Initialize (S); Need ("runtime");
   declare Seed1 : constant Digest := (others => 1); Seed2 : constant Digest := (others => 2); begin
      Expect (Keypair (PK1'Address, SK1'Address, Seed1'Address) = 0, "test validator key");
      Expect (Keypair (PK2'Address, SK2'Address, Seed2'Address) = 0, "test reviewer key");
   end;
   MC_Store.Initialize (Store_Path, Store, S); Need ("initialize fixture CAS");
   MC_Store.Put (Store, Bytes'(0, 0), Attrs, S); Need ("empty attributes");
   MC_Store.Put (Store, Bytes'(7, 8, 9), Receipt, S); Need ("synthetic health receipt"); MC_Store.Close (Store);
   Build (1);
   declare Wire : GD.Frame := GD.Encode (After); begin
      GD.Decode (Wire, Decoded, S); Need ("decode descriptor"); Expect (Decoded = After, "canonical descriptor round trip");
      Expect (MC_Hex.Encode (Wire (105 .. 112)) = "0000000000000001", "generation uses network byte order");
      Wire (145) := 1; Wire (161 .. 192) := MC_SHA256.Hash (Wire (1 .. 160));
      GD.Decode (Wire, Decoded, S); Expect (S = Corrupt, "reserved byte rejected with valid checksum");
      Wire := GD.Encode (After); Wire (161) := Wire (161) xor 1;
      GD.Decode (Wire, Decoded, S); Expect (S = Corrupt, "descriptor checksum rejected");
      GD.Decode (GD.Encode (After) (1 .. 191), Decoded, S); Expect (S = Corrupt, "short descriptor rejected");
      declare Trailing : Bytes (1 .. 193) := (others => 0); Shifted : Bytes (2 .. 193); begin
         Trailing (1 .. 192) := GD.Encode (After); Shifted := GD.Encode (After);
         GD.Decode (Trailing, Decoded, S); Expect (S = Corrupt, "trailing descriptor byte rejected");
         GD.Decode (Shifted, Decoded, S); Expect (S = Corrupt, "noncanonical descriptor indexing rejected");
      end;
      Other := After; Other.Previous := Mark; Expect (not GD.Valid (Other), "first generation cannot name a predecessor");
      Other := After; Other.Stage_ID := Other.Root_ID; Expect (not GD.Valid (Other), "stage and publication roots must differ");
   end;
   if MC_Posix.Euid = 0 then
      Publisher.Provision (Root_Path, State_Path, Root_ID, Grant, S); Expect (S = Denied, "root publication provision refused");
      Publish; Expect (S = Denied, "root publication refused");
      Read_Current; Expect (S = Denied and then Current = GD.Empty, "root readback refused"); Report; return;
   end if;
   Inject := Bootstrap_Denied; Publisher.Provision (Root_Path, State_Path, Root_ID, Grant, S);
   Expect (S = Denied, "bootstrap requires authority"); Inject := None;
   Publisher.Provision (Root_Path, State_Path, Root_ID, Grant, S); Need ("provision publication authority");
   Publisher.Provision (Root_Path, State_Path, Root_ID, Grant, S); Expect (S = Conflict, "no rebootstrap");
   MC_FS.Open_Root (State_Path, State, S, Private_Only => True); Need ("initial publication state fixture");
   declare Frame : Pkg_Root_State.Frame; RS : Pkg_Root_State.State; begin
      MC_Atomic.Read (State, "root.state", Frame, Used, S); Need ("retain initial state");
      Pkg_Root_State.Decode (Frame, RS, S); Need ("decode initial state"); RS.Accepted_Plan := Plan_Hash;
      MC_Atomic.Write (State, "root.state", Pkg_Root_State.Encode (RS), False, S); Need ("inject contradictory initial state");
      Read_Current; Expect (S = Corrupt and then Current = GD.Empty, "zero generation cannot hide an accepted plan");
      Publish; Expect (S = Corrupt, "contradictory initial state cannot bootstrap via publish");
      MC_Atomic.Write (State, "root.state", Frame, False, S); Need ("restore exact initial state");
   end; MC_FS.Close (State);
   Read_Current; Expect (S = Stale and then Current = GD.Empty, "no fictitious initial generation");
   Publish; Expect (S = Conflict, "incomplete stage cannot publish"); Complete_Stage;
   Check_Plan_Restrictions;
   for F in Authority_Denied .. Current_Changed loop
      Inject := F; Publish; Expect (S /= OK, "composed gate refuses " & Fault'Image (F));
      Read_Current; Expect (S = Stale and then Current = GD.Empty, "denied preparation leaves no accepted generation");
   end loop;
   Inject := Stage_Denied; Publish; Expect (S = Denied, "stage reservation requires independent authority");
   Inject := Commit_Denied; Publish; Expect (S = Denied, "commit can be revoked after file application");
   Read_Current; Expect (S = Indeterminate and then Current = GD.Empty, "candidate file is not current during denied commit");
   Inject := None; Publish; Need ("resume first publication");
   Read_Current; Need ("read first publication"); Expect (Current = After, "first root/catalog pair exact");
   Publish; Need ("idempotent publication retry");
   Publisher.Publish (Root_Path, State_Path, Store_Path, Bank, Plan_Hash, Mark, S);
   Expect (S = Denied, "recorded health receipt cannot be replaced on retry");
   Publisher.Read_Current (Root_Path, State_Path, Store_Path, Boot, Current, S);
   Expect (S = Denied and then Current = GD.Empty, "readback is bound to publication root identity");
   Expect (Probed and then Config_Calls > 0 and then Native_Calls > 0 and then Recheck_Calls > 0, "full managed gates were reached under reservations");
   First_Plan := Plan_Hash; First_Tx := P.Transaction_ID; Before := After;
   Build (2); Complete_Stage;
   Check_Plan_Restrictions;
   Other := After; Other.Previous := Mark;
   GD.Compile (Before, Other, P.Transaction_ID, 1, 2, Mark, Word (MC_Posix.Euid), Word (MC_Posix.Egid), Batch.all, S);
   Expect (S = Invalid_Input, "incorrect predecessor hash refused before publication");
   MC_FS.Open_Root (Root_Path, Root, S, Private_Only => True); Need ("fixture publication root");
   MC_FS.Open_Root (State_Path, State, S, Private_Only => True); Need ("fixture publication state");
   declare Name : constant String := "tx-" & MC_Hex.Encode (First_Tx) & ".log"; begin
      MC_FS.Rename (State, Name, "retained-journal", True, S); Need ("retain preceding journal");
      Publish; Expect (S = Corrupt, "missing accepted journal blocks new transaction");
      Read_Current; Expect (S = Corrupt and then Current = GD.Empty, "missing accepted journal blocks readback");
      MC_FS.Rename (State, "retained-journal", Name, True, S); Need ("restore preceding journal");
   end;
   Inject := Commit_Denied; Publish; Expect (S = Denied, "second decision can stop after candidate write");
   MC_Atomic.Read (Root, "generation.next", B.all, Used, S); Need ("observe unpublished candidate fixture");
   GD.Decode (B (1 .. Used), Other, S); Need ("decode candidate fixture"); Expect (Other = After, "candidate already contains second generation");
   Read_Current; Expect (S = Indeterminate and then Current = GD.Empty, "candidate never overrides active transaction state");
   Inject := None; Publish; Need ("resume second publication");
   Read_Current; Need ("read second publication"); Expect (Current = After, "second root/catalog pair exact");
   Commit_Window (False, False); Commit_Window (True, False); Commit_Window (True, True);
   Ada.Directories.Rename (Root_Path & "/generation.next", State_Path & "/retained-candidate");
   MC_Atomic.Write (Root, "generation.next", GD.Encode (Before), True, S); Need ("replace candidate with stale fixture descriptor");
   Read_Current; Need ("read accepted CAS despite stale scratch file"); Expect (Current = After, "scratch does not redirect reader");
   Publish; Expect (S = Conflict, "reconciliation still rejects mismatched physical scratch");
   MC_FS.Remove (Root, "generation.next", False, S); Need ("remove stale scratch");
   Ada.Directories.Rename (State_Path & "/retained-candidate", Root_Path & "/generation.next");
   Publish; Need ("reconciliation after exact scratch restoration");
   MC_FS.Rename (State, "publication.lock", "retained-lock", True, S); Need ("retain publication lock");
   Publish; Expect (S = Corrupt, "missing publication lock not replaced");
   Read_Current; Expect (S = Corrupt and then Current = GD.Empty, "missing publication lock blocks reader");
   MC_FS.Rename (State, "retained-lock", "publication.lock", True, S); Need ("restore publication lock");
   declare CAS : MC_FS.Root; Hash : constant String := MC_Hex.Encode (P.Changes (1).After.Content);
      Path : constant String := "objects/" & Hash (1 .. 2) & "/" & Hash (3 .. 64);
   begin
      MC_FS.Open_Root (Store_Path, CAS, S, Private_Only => True); Need ("fixture CAS directory");
      MC_FS.Rename (CAS, Path, "retained-descriptor", True, S); Need ("retain accepted CAS descriptor");
      Read_Current; Expect (S /= OK and then Current = GD.Empty, "missing CAS descriptor not replaced by scratch");
      Publish; Expect (S /= OK, "missing CAS descriptor blocks retry");
      MC_FS.Rename (CAS, "retained-descriptor", Path, True, S); Need ("restore accepted CAS descriptor"); MC_FS.Close (CAS);
   end;
   Read_Current; Need ("final exact readback"); Expect (Current = After, "final generation retained");
   declare Name : constant String := "tx-" & MC_Hex.Encode (P.Transaction_ID) & ".log";
      Journal : MC_FS.File; Info : MC_FS.Entry_Info;
   begin
      MC_Atomic.Read (State, Name, B.all, Used, S); Need ("retain final journal fixture bytes");
      MC_FS.Open_Locked (State, Name, Journal, S, Create_If_Missing => False); Need ("open journal for disposable torn-tail fixture");
      MC_FS.Append_Durable (Journal, Counter (Used), Bytes'(1 => 99), S); Need ("append synthetic partial record"); MC_FS.Close (Journal);
      Read_Current; Expect (S = Indeterminate and then Current = GD.Empty, "torn accepted journal cannot authorize readback");
      Publish; Expect (S = Indeterminate, "torn journal cannot be repaired by publication retry");
      MC_FS.Stat (State, Name, Info, S); Need ("observe retained partial journal");
      Expect (Info.Size = Counter (Used + 1), "publication preserves unknown journal suffix");
      MC_Atomic.Write (State, Name, B (1 .. Used), False, S); Need ("restore exact final journal fixture");
   end;
   Read_Current; Need ("final restored journal readback"); Expect (Current = After, "exact final publication");
   MC_FS.Close (Root); MC_FS.Close (State); Report;
exception when others => MC_Store.Close (Store); MC_FS.Close (Root); MC_FS.Close (State); raise;
end Run_Generation_Publication_Tests;
