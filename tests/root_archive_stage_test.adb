-- SPDX-License-Identifier: BSD-3-Clause
-- Artificial signatures and exact fixture authorization; never a site provider.
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO; with Ada.Unchecked_Deallocation; with Interfaces.C; with System;
with MC_Clock; with Pkg_Root_Preparation; with MC_Codec; with MC_FS; with MC_Hex; with MC_Posix; with MC_SHA256; with MC_Text;
with Pkg_Configured_Root; with Pkg_Conffile_Choice; with Pkg_Conffile_Transition; with Pkg_Root_Configuration;
with Pkg_Archive_Supply; with Pkg_Supply_Map; with Pkg_Supply_Policy;
with Pkg_Deb_Final_Set; with Pkg_File_Plan; with Pkg_Generation_Descriptor;
with Pkg_Generation_Intent; with Pkg_Generation_Manifest; with Pkg_Generation_Stage;
with Test_Support; use Test_Support;
package body Root_Archive_Stage_Test with SPARK_Mode => Off is
   package GM renames Pkg_Generation_Manifest; package FP renames Pkg_File_Plan;
   use type Interfaces.C.int; use type Interfaces.C.unsigned_long_long; use type Byte;
   use type Wide; use type GM.Manifest; use type MC_FS.Entry_Kind;
   procedure Run (Store : in out MC_Store.Store; Store_Path : String;
      Catalog, Closure, Root_Manifest, Archive : Digest;
      Packages : Pkg_Selected_Catalog.Selection; Deadline : Counter;
      Source_FD : Integer := -1; Prior, Incoming : Digest := Zero_Digest) is
      Configured : constant Boolean := Source_FD >= 0;
      Selected_Archive : Digest := Archive;
      Status : Outcome; Root_ID : constant Identity := (others => 84);
      M, Decoded : GM.Manifest;
      Expected, Receipt, Attrs, Ignored, Map : Digest; PK : Digest; SK : Bytes (1 .. 64);
      Seed : constant Digest := (others => 85); Until_Time : Counter;
      Trust : Pkg_Supply_Map.Authorities (1 .. 1);
      Rows : Pkg_Supply_Map.Sources (Packages'Range);
      Target : constant Pkg_Supply_Map.Context := (Root_ID, Pkg_Generation_Descriptor.Empty, Zero_Digest, Catalog, Closure);
      Enabled : Pkg_Deb_Final_Set.Architecture_List (1 .. 1);
      type Plan_Access is access FP.Plan;
      procedure Free is new Ada.Unchecked_Deallocation (FP.Plan, Plan_Access);
      Plan : Plan_Access := new FP.Plan;
      type Digest_Array is array (Positive range <>) of Digest;
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Raw_Plan : Buffer_Access := new Bytes (1 .. FP.Max_Plan_Bytes);
      Wire, Changed : Bytes (1 .. GM.Max_Bytes); Used, Count : Natural;
      File : MC_FS.File; CAS, Stage_Root : MC_FS.Root; Info : MC_FS.Entry_Info;
      Parent : constant String := Ada.Directories.Containing_Directory (Store_Path);
      Root_Path : constant String := Parent & "/archive-stage-root";
      State_Path : constant String := Parent & "/archive-stage-state";
      Deny, Deny_Prepare, Deny_Post : Boolean := False;
      Prepare_Calls, Post_Calls, Source_Calls, Input_Calls : Natural := 0;
      Reinspection_Mode : Natural := 0;
      Foreign_Root : MC_Posix.FD := -1; Closed : Interfaces.C.int;
      Deny_Source, Deny_Inputs, Missing_FD, Wrong_Source : Boolean := False;
      function Keypair (PK, SK, Seed : System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "crypto_sign_seed_keypair";
      function Sign (Signature, Length, Message : System.Address;
         Size : Interfaces.C.unsigned_long_long; SK : System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "crypto_sign_detached";
      procedure Need (Name : String) is
      begin Expect (Status = OK, Name & Outcome'Image (Status)); end Need;
      procedure Authorize (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
         Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
      begin
         Status := Denied;
         if Phase in "stage:prepare-root" | "stage:root-prepared" | "stage:reinspect-root" | "stage:root-reinspected" then
            declare Other : MC_Store.Store; Result : Outcome; begin
               MC_Store.Open (Store_Path, Other, Result);
               Expect (Result /= OK, "actual CAS reservation remains held during admission");
               MC_Store.Close (Other);
            end;
         end if;
         if Phase = "stage:prepare-root" then
            Prepare_Calls := Prepare_Calls + 1; if Deny_Prepare then return; end if;
         elsif Phase = "stage:root-prepared" then
            Post_Calls := Post_Calls + 1; if Deny_Post then return; end if;
         end if;
         if Reinspection_Mode = 5 and then Phase = "stage:root-reinspected" then return; end if;
         if Deny or else Manifest /= Expected or else Stage_ID /= M.Stage_ID or else Epoch /= M.Epoch
           or else Fence /= M.Fence or else Phase'Length <= 6 or else Phase (Phase'First .. Phase'First + 5) /= "stage:" then return; end if;
         if Plan = Zero_Digest then
            if Transaction_ID = M.Transaction_ID and then Evidence = Zero_Digest
              and then Phase in "stage:provision" | "stage:provision-root" | "stage:advance" |
                "stage:inspect" | "stage:inspect-batch" | "stage:inspected" |
                "stage:prepare-root" | "stage:root-prepared" | "stage:reinspect-root" | "stage:root-reinspected" then Status := OK; end if;
         elsif Plan = M.Batches (1).Plan and then Transaction_ID = GM.Transaction (M, 1)
           and then Evidence in Zero_Digest | Receipt then Status := OK; end if;
      end Authorize;
      procedure Observe (Generation : Digest; Root_ID, Transaction_ID : Identity;
         Context : Digest; Phase : String; Root_FD : out Integer; Status : out Outcome) is
         Other : MC_Store.Store; Result : Outcome;
      begin
         Root_FD := -1; Status := Denied; Source_Calls := Source_Calls + 1;
         if Phase = "stage:advance-inputs" then Input_Calls := Input_Calls + 1; end if;
         if Deny_Source or else (Deny_Inputs and then Phase = "stage:advance-inputs") then return; end if;
         if not Configured or else Generation /= Expected or else Root_ID /= Identity'(others => 84)
           or else Transaction_ID /= M.Transaction_ID or else Context /= M.Intent
           or else Phase not in "stage:provision" | "stage:advance" | "stage:advance-inputs" |
             "stage:inspect" | "stage:prepare-root" | "stage:root-prepared" | "stage:reinspect-root" | "stage:root-reinspected" then return; end if;
         MC_Store.Open (Store_Path, Other, Result);
         Expect (Result /= OK, "source observation uses actual stage or engine CAS reservation"); MC_Store.Close (Other);
         if not Missing_FD then Root_FD := (if Wrong_Source and then Phase = "stage:advance-inputs" then Integer (Foreign_Root) else Source_FD); end if; Status := OK;
      end Observe;
      package Stage is new Pkg_Generation_Stage (Authorize, Observe);
      package Default_Stage is new Pkg_Generation_Stage (Authorize);
      Transport_Calls, Transport_Mode : Natural := 0;
      procedure Transport (Generation, Root_Manifest, Archive, Worker : Digest; Stage_ID : Identity;
         Size, Entries, Until_Time : Counter; Archive_FD, Reservation_FD : Integer; Result : out Outcome) is
         Other : MC_Store.Store; R : MC_FS.Root; L : MC_FS.File; Check : Outcome;
      begin
         Transport_Calls := Transport_Calls + 1;
         Expect (Generation = Expected and then Root_Manifest = (if Configured then M.Configured_Root else M.Root_Archive)
            and then Archive = Selected_Archive and then Worker = Receipt and then Stage_ID = M.Stage_ID
            and then Size > 0 and then Entries > 0 and then Until_Time = Deadline
            and then Archive_FD >= 0 and then Reservation_FD >= 0, "transport receives exact native scope and real FDs");
         MC_Store.Open (Store_Path, Other, Check); Expect (Check = Conflict, "transport retains CAS reservation"); MC_Store.Close (Other);
         MC_FS.Open_Root (State_Path, R, Check); Expect (Check = OK, "transport stage directory");
         MC_FS.Open_Locked (R, "generation.lock", L, Check, Create_If_Missing => False);
         Expect (Check = Conflict, "transport retains stage reservation"); MC_FS.Close (L);
         MC_FS.Open_Locked (R, "root.lock", L, Check, Create_If_Missing => False);
         Expect (Check = Conflict, "transport retains root reservation"); MC_FS.Close (L); MC_FS.Close (R);
         Result := (if Transport_Mode = 0 then Denied else OK);
         if Transport_Mode = 2 then Deny_Post := True; end if;
         if Transport_Mode = 3 then raise Constraint_Error with "private transport fault"; end if;
      end Transport;
      procedure Prepare_Using is new Stage.Prepare_Root_Using (Transport);
      procedure Transport_Checks is
         Other : MC_Store.Store;
      begin
         Deny_Prepare := True;
         Prepare_Using (Root_Path, State_Path, Store_Path, Expected, Receipt, Deadline, Status);
         Expect (Status = Denied and then Transport_Calls = 0, "denied native admission cannot invoke transport");
         Deny_Prepare := False;
         for Mode in 0 .. 3 loop
            Transport_Mode := Mode;
            Prepare_Using (Root_Path, State_Path, Store_Path, Expected, Receipt, Deadline, Status);
            Expect (Status = (if Mode = 1 then OK else Indeterminate), "transport does not hide uncertain delivery or post denial");
            Deny_Post := False;
            MC_Store.Open (Store_Path, Other, Status); Need ("transport result releases native reservation"); MC_Store.Close (Other);
         end loop;
         Expect (Transport_Calls = 4, "one callback for each admitted operation");
         Prepare_Calls := 0; Post_Calls := 0;
      end Transport_Checks;

      procedure Physical_Observation (Generation : Digest; Stage_ID : Identity; Phase : String;
         Original_Deadline : out Counter; Root : out Pkg_Root_Preparation.Root_Identity; Result : out Outcome) is
         Input : Ada.Text_IO.File_Type;
      begin
         Original_Deadline := 0; Root := (others => <>); Result := Denied;
         if Reinspection_Mode = 1 or else Generation /= Expected or else Stage_ID /= M.Stage_ID
           or else Phase not in "stage:reinspect-root" | "stage:root-reinspected" then return; end if;
         -- Explicit VM fixture bridge, not a production mount/authority provider.
         Ada.Text_IO.Open (Input, Ada.Text_IO.In_File, Parent & "/frozen-root.txt");
         Original_Deadline := Counter'Value (Ada.Text_IO.Get_Line (Input));
         Root.Mount_ID := Wide'Value (Ada.Text_IO.Get_Line (Input));
         Root.Inode := Wide'Value (Ada.Text_IO.Get_Line (Input));
         Root.Device_Major := Word'Value (Ada.Text_IO.Get_Line (Input));
         Root.Device_Minor := Word'Value (Ada.Text_IO.Get_Line (Input));
         Ada.Text_IO.Close (Input);
         if Reinspection_Mode = 2 or else (Reinspection_Mode = 4 and then Phase = "stage:root-reinspected") then
            Root.Mount_ID := Root.Mount_ID + 1;
         elsif Reinspection_Mode = 3 then Original_Deadline := Original_Deadline + 1; end if;
         Result := OK;
      exception when others => if Ada.Text_IO.Is_Open (Input) then Ada.Text_IO.Close (Input); end if; Result := Denied;
      end Physical_Observation;
      procedure Reinspect is new Stage.Reinspect_Root_And_Hold (Physical_Observation);
      procedure Physical_Checks (Socket_Path : String; Worker : Digest) is
         use type Pkg_Root_Preparation.Root_Identity;
         C : Stage.Reinspected_Generation; Other : MC_Store.Store;
         Other_Root : MC_FS.Root; Other_Lock : MC_FS.File; Result : Outcome; Until_Time, Now : Counter;
         Saved : Pkg_Root_Preparation.Root_Identity;
         procedure Reservations is
         begin
            MC_Store.Open (Store_Path, Other, Result); Expect (Result = Conflict, "reinspection handle retains CAS"); MC_Store.Close (Other);
            MC_FS.Open_Root (State_Path, Other_Root, Result); Expect (Result = OK, "open reserved stage");
            MC_FS.Open_Locked (Other_Root, "generation.lock", Other_Lock, Result, Create_If_Missing => False);
            Expect (Result = Conflict, "reinspection handle retains stage reservation"); MC_FS.Close (Other_Lock); MC_FS.Close (Other_Root);
            MC_FS.Open_Root (State_Path, Other_Root, Result); Expect (Result = OK, "open root reservation directory");
            MC_FS.Open_Locked (Other_Root, "root.lock", Other_Lock, Result, Create_If_Missing => False);
            Expect (Result = Conflict, "reinspection handle retains root reservation"); MC_FS.Close (Other_Lock); MC_FS.Close (Other_Root);
         end Reservations;
      begin
         -- Parent VM freezes the real tree before exposing this fixture bridge.
         loop
            exit when Ada.Directories.Exists (Parent & "/frozen-root.txt");
            MC_Clock.Boottime_Milliseconds (Now, Status); Need ("wait for private freeze");
            Expect (Now < Deadline, "private freeze wait bounded"); delay 0.01;
         end loop;
         for Mode in 1 .. 5 loop
            Reinspection_Mode := Mode;
            Reinspect (Root_Path, State_Path, Store_Path, Socket_Path, Expected, Worker, C, Deadline, Status);
            Expect (Status = (if Mode = 1 then Denied else Indeterminate), "reinspection boundary refusal" & Natural'Image (Mode));
            Expect (not Stage.Held (C) and then Stage.Root_Observation (C) = Pkg_Root_Preparation.Root_Identity'(others => <>), "failure exposes no root observation");
            MC_Store.Open (Store_Path, Other, Status); Need ("failure releases native CAS reservation mode" & Natural'Image (Mode)); MC_Store.Close (Other);
            Ada.Text_IO.Put_Line ("PASS native reinspection refusal mode" & Natural'Image (Mode));
         end loop;
         Reinspection_Mode := 0; MC_Clock.Boottime_Milliseconds (Now, Status); Need ("reinspection deadline"); Until_Time := Now + 3_000;
         Reinspect (Root_Path, State_Path, Store_Path, Socket_Path, Expected, Worker, C, Until_Time, Status); Need ("native physical observation and retained reservations");
         Expect (Stage.Held (C), "live reinspected root handle"); Saved := Stage.Root_Observation (C);
         Expect (Saved.Mount_ID /= 0 and then Saved.Inode /= 0, "actual frozen root identity"); Reservations;
         Reinspect (Root_Path, State_Path, Store_Path, Socket_Path, Expected, Worker, C, Deadline, Status);
         Expect (Status = Conflict and then Stage.Root_Observation (C) = Saved, "busy handle cannot silently release or replace observations");
         loop
            MC_Clock.Boottime_Milliseconds (Now, Status); Need ("bounded expiry clock"); exit when Now >= Until_Time; delay 0.05;
         end loop;
         Expect (not Stage.Held (C) and then Stage.Root_Observation (C) = Pkg_Root_Preparation.Root_Identity'(others => <>), "expired handle exposes no observation"); Reservations;
         Stage.Close (C); Stage.Close (C);
         MC_Store.Open (Store_Path, Other, Status); Need ("explicit Close releases CAS"); MC_Store.Close (Other);
         Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status); Need ("explicit Close releases stage and root");
         Ada.Text_IO.Put_Line ("PASS native reinspection binding, post-gates, retained reservations and expiry");
      exception when others => Stage.Close (C); MC_Store.Close (Other); MC_FS.Close (Other_Lock); MC_FS.Close (Other_Root); raise;
      end Physical_Checks;
      function Object_Path (Hash : Digest) return String is
         Hex : constant String := MC_Hex.Encode (Hash);
      begin return "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64); end Object_Path;
   begin
      MC_Store.Put (Store, Bytes'(17, 18, 19), Receipt, Status); Need ("fixture receipt");
      MC_Store.Put (Store, Bytes'(0, 0), Attrs, Status); Need ("fixture empty xattrs");
      M := (Format => GM.Root_V5, Catalog => Catalog, Catalog_Closure => Closure, Root_Archive => Root_Manifest,
         Stage_ID => (others => 86), Transaction_ID => (others => 87), Epoch => 1, Fence => 2,
         Effect_Contract => Receipt, Entries => 3, Count => 1, others => <>);
      MC_Text.Set (Enabled (1), "amd64", Status); Need ("explicit architecture");
      Pkg_Generation_Intent.Prepare (Store, Root_ID, Pkg_Generation_Descriptor.Empty, Zero_Digest,
         Catalog, Closure, "amd64", Enabled, Deadline, M.Intent, Ignored, Status); Need ("root generation intent");
      Expect (Keypair (PK'Address, SK'Address, Seed'Address) = 0, "public fixture key");
      Trust (1) := (Scope => (others => 88), Key => PK, Minimum_Epoch => 7, Maximum_Age => 600);
      for I in Packages'Range loop
         declare
            Receipt_Wire : Bytes (1 .. Pkg_Archive_Supply.Wire_Size) := (others => 0);
            Domain : constant String := "NiaOS/archive-supply/v1";
            Message : Bytes (1 .. 2 + Domain'Length + Pkg_Archive_Supply.Body_Size);
            Length : aliased Interfaces.C.unsigned_long_long := 0;
         begin
            Rows (I).Original := Packages (I).Original; Rows (I).Control := Packages (I).Control;
            Receipt_Wire (1 .. 8) := (78, 73, 65, 83, 85, 80, 48, 49); Receipt_Wire (9 .. 40) := Trust (1).Scope;
            Receipt_Wire (41 .. 72) := Receipt; Receipt_Wire (73 .. 104) := Packages (I).Original;
            Receipt_Wire (105 .. 136) := Packages (I).Control;
            Receipt_Wire (137 .. 168) := Receipt; Receipt_Wire (169 .. 200) := Receipt; Receipt_Wire (201 .. 232) := Receipt;
            MC_Codec.Put64 (Receipt_Wire, 233, 7); MC_Codec.Put64 (Receipt_Wire, 241, 1_000);
            MC_Codec.Put64 (Receipt_Wire, 249, 1_600); MC_Codec.Put16 (Message, 1, Domain'Length);
            for J in Domain'Range loop Message (J + 2) := Byte (Character'Pos (Domain (J))); end loop;
            Message (Domain'Length + 3 .. Message'Last) := Receipt_Wire (1 .. Pkg_Archive_Supply.Body_Size);
            Expect (Sign (Receipt_Wire (257)'Address, Length'Address, Message'Address, Message'Length, SK'Address) = 0
               and then Length = 64, "signed fixture original");
            MC_Store.Put (Store, Receipt_Wire, Rows (I).Receipt, Status); Need ("retained fixture receipt");
         end;
      end loop;
      Pkg_Supply_Map.Prepare (Store, Target, Rows, Trust, 1_000, Deadline, Map, Until_Time, Status); Need ("root supply map");
      Pkg_Supply_Policy.Prepare (Store, Map, Target, Trust, 1_000, Deadline,
         M.Supply_Policy, Until_Time, Status); Need ("root supply policy");
      if Configured then
         declare Proposal : aliased Pkg_Conffile_Choice.Proposal; Decision, Kept : Digest;
            Choices : Pkg_Root_Configuration.Choices (1 .. 1);
         begin
            M.Format := GM.Configured_V6;
            Pkg_Conffile_Choice.Prepare (Store, Source_FD, Root_ID, M.Transaction_ID, M.Intent,
               Pkg_Conffile_Choice.Update, "/etc/fixture.conf", Prior, Incoming, MC_Store.Max_Object_Size,
               Deadline, Proposal, Status); Need ("generation-scoped current proposal");
            Pkg_Conffile_Choice.Resolve (Store, Proposal, Pkg_Conffile_Choice.Address (Proposal),
               Pkg_Conffile_Transition.Keep_Local, "/etc/fixture.conf.save", Deadline, Decision, Kept, Status);
            Need ("generation-scoped retained choice");
            Choices (1) := (Proposal'Unchecked_Access, Decision, Kept);
            Pkg_Configured_Root.Build (Store, Root_Manifest, Catalog, Closure, Root_ID, M.Transaction_ID, M.Intent,
               "amd64", Choices, MC_Store.Max_Object_Size, Deadline, M.Configured_Root, Selected_Archive,
               M.Configuration_Closure, Status); Need ("complete configured generation output");
         end;
      end if;
      FP.Clear (Plan.all); Plan.Root_ID := M.Stage_ID; Plan.Transaction_ID := GM.Transaction (M, 1);
      Plan.Target_Generation := 1; Plan.Epoch := M.Epoch; Plan.Fence := M.Fence;
      Plan.Package_Set := Catalog; Plan.Effect_Contract := Receipt; Plan.Count := 3;
      MC_Store.Open_Object (Store, Catalog, File, Status); Need ("catalog object");
      MC_FS.Info (File, Info, Status); Need ("catalog size"); MC_FS.Close (File);
      MC_Text.Set (Plan.Changes (1).Path, "catalog", Status); Need ("catalog path");
      Plan.Changes (1).After := (Node_Kind => FP.Regular, Mode => 8#400#, UID => Word (MC_Posix.Euid),
         GID => Word (MC_Posix.Egid), Size => Info.Size, Content => Catalog, Xattrs => Attrs, others => <>);
      MC_Text.Set (Plan.Changes (2).Path, "tree", Status); Need ("tree path");
      Plan.Changes (2).After := (Node_Kind => FP.Directory, Mode => 8#755#, UID => Word (MC_Posix.Euid),
         GID => Word (MC_Posix.Egid), Xattrs => Attrs, others => <>);
      MC_Store.Open_Object (Store, Selected_Archive, File, Status); Need ("assembled tar object");
      MC_FS.Info (File, Info, Status); Need ("assembled tar size"); MC_FS.Close (File);
      MC_Text.Set (Plan.Changes (3).Path, "tree/root.tar", Status); Need ("archive path");
      Plan.Changes (3).After := Plan.Changes (1).After; Plan.Changes (3).After.Content := Selected_Archive;
      Plan.Changes (3).After.Size := Info.Size;
      FP.Encode (Plan.all, Raw_Plan.all, Count, Status); Need ("root stage plan");
      MC_Store.Put (Store, Raw_Plan (1 .. Count), M.Batches (1).Plan, Status); Need ("retain stage plan");
      M.Batches (1).Receipt := Receipt;
      GM.Encode (M, Wire, Used, Status); Need ("root manifest encode");
      Expect (Used = (if Configured then 384 else 320) and then Wire (8) = (if Configured then 54 else 53)
         and then Wire (225 .. 256) = Root_Manifest, "versioned root header exact");
      if Configured then
         Expect (MC_Hex.Encode (GM.Transaction (M, 1)) = "e6998ebd60a56c5edfc5d06ce5178042", "v6 transaction independent SHA256 vector");
         Expect (Wire (257 .. 288) = M.Configured_Root and then Wire (289 .. 320) = M.Configuration_Closure,
            "v6 retains configured record and exact closure separately from base");
         for Position in 0 .. 1 loop
            Changed := Wire; Changed (257 + 32 * Position .. 288 + 32 * Position) := Zero_Digest;
            GM.Decode (Changed (1 .. Used), Decoded, Status);
            Expect (Status /= OK and then Decoded = GM.Manifest'(others => <>), "configured references mandatory");
         end loop;
         for Length in 257 .. 319 loop
            GM.Decode (Wire (1 .. Length), Decoded, Status);
            Expect (Status /= OK and then Decoded = GM.Manifest'(others => <>), "truncated configured header clears output");
         end loop;
         Decoded := M; Decoded.Format := GM.Root_V5;
         Expect (not GM.Valid (Decoded), "v5 cannot silently carry configured fields");
      end if;
      GM.Decode (Wire (1 .. Used), Decoded, Status); Need ("root manifest decode"); Expect (Decoded = M, "root format round trip");
      for Tag in Byte range 49 .. (if Configured then 53 else 52) loop
         Changed := Wire; Changed (8) := Tag; GM.Decode (Changed (1 .. Used), Decoded, Status);
         Expect (Status /= OK and then Decoded = GM.Manifest'(others => <>), "root profile cannot be relabeled");
      end loop;
      Changed := Wire; Changed (225 .. 256) := Zero_Digest; GM.Decode (Changed (1 .. Used), Decoded, Status);
      Expect (Status /= OK and then Decoded = GM.Manifest'(others => <>), "root reference is mandatory");
      Decoded := M; Decoded.Format := GM.Supply_V4; Expect (not GM.Valid (Decoded), "v4 cannot silently carry a root reference");
      Decoded := M; Decoded.Entries := 4; Expect (not GM.Valid (Decoded), "root profile excludes additional staged entries");
      GM.Check_Retention (Store, M, 0, Status); Expect (Status = Stale, "root retention deadline");
      GM.Check_Retention (Store, M, Counter'Last, Status); Expect (Status = Invalid_Input, "root retention deadline must be finite");
      GM.Check (Store, M, Status); Need ("root stage structure");
      GM.Check_Retention (Store, M, Deadline, Status); Need ("complete root generation retention");
      -- A valid ordinary-file plan is insufficient if it carries different bytes.
      Plan.Changes (3).After.Content := Catalog;
      FP.Encode (Plan.all, Raw_Plan.all, Count, Status); Need ("wrong root content plan");
      MC_Store.Put (Store, Raw_Plan (1 .. Count), Ignored, Status); Need ("retain mismatched plan");
      Decoded := M; Decoded.Batches (1).Plan := Ignored;
      GM.Check_Retention (Store, Decoded, Deadline, Status); Expect (Status = Conflict, "manifest binds exact staged root tar");
      if Configured then
         Decoded := M; Decoded.Intent := Receipt;
         GM.Check_Retention (Store, Decoded, Deadline, Status); Expect (Status /= OK, "configured intent cannot be substituted");
      end if;
      MC_Store.Put (Store, Wire (1 .. Used), Expected, Status); Need ("retained v5 manifest");
      Ada.Text_IO.Put_Line ("GENERATION_MANIFEST " & MC_Hex.Encode (Expected));
      MC_Store.Close (Store);
      Ada.Directories.Create_Directory (Root_Path); Ada.Directories.Create_Directory (State_Path);
      if Configured then
         Default_Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status);
         Expect (Status = Denied, "legacy instantiation refuses configured root without provider");
         Deny_Source := True;
         Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status);
         Expect (Status = Denied, "configured provision requires independent source admission"); Deny_Source := False;
         Missing_FD := True;
         Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status);
         Expect (Status = Denied, "successful source callback without FD cannot bypass current check"); Missing_FD := False;
         Expect (not Ada.Directories.Exists (State_Path & "/generation.manifest"), "refused source creates no generation binding");
      end if;
      Deny := True; Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status);
      Expect (Status = Denied, "root archive stage still needs independent authorization"); Deny := False;
      Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status); Need ("provision versioned root stage");
      if Configured then
         Deny_Inputs := True;
         Stage.Advance (Root_Path, State_Path, Store_Path, Expected, Count, Deadline, Status);
         Expect (Status = Denied and then Count = 0 and then Input_Calls = 1,
            "inner engine reacquisition requires new source admission before mutation"); Deny_Inputs := False;
         Expect (not Ada.Directories.Exists (Root_Path & "/catalog"), "refused inner source creates no staged catalog");
         declare Name : aliased constant String := Root_Path & ASCII.NUL; begin
            Foreign_Root := MC_Posix.Open (Name'Address, MC_Posix.O_PATH + MC_Posix.O_DIRECTORY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
            Expect (Foreign_Root >= 0, "different source root fixture");
         end;
         Wrong_Source := True;
         Stage.Advance (Root_Path, State_Path, Store_Path, Expected, Count, Deadline, Status);
         Expect (Status /= OK and then Count = 0, "provider success with different physical source is not current evidence");
         Wrong_Source := False; Closed := MC_Posix.Close (Foreign_Root); Foreign_Root := -1;
         Expect (not Ada.Directories.Exists (Root_Path & "/catalog"), "different source caused no stage effect");
      end if;
      Stage.Advance (Root_Path, State_Path, Store_Path, Expected, Count, Deadline, Status); Need ("materialize root archive stage");
      Expect (Count = 1, "one root archive batch");
      if Configured then Expect (Input_Calls = 4, "both actual engine reservations reobserve configuration"); end if;
      Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status); Need ("inspect exact root stage");
      Transport_Checks;
      Deny_Prepare := True;
      Stage.Prepare_Root (Root_Path, State_Path, Store_Path, "/nonexistent-preparation.sock",
         Expected, Receipt, Deadline, Status);
      Expect (Status = Denied and then Prepare_Calls = 1 and then Post_Calls = 0, "preparation requires its own live authorization");
      Deny_Prepare := False;
      if Ada.Command_Line.Argument_Count >= (if Configured then 5 else 4) then
         declare
            Worker : Digest; Shift : constant Natural := (if Configured then 1 else 0);
         begin
            MC_Hex.Decode (Ada.Command_Line.Argument (4 + Shift), Worker, Status); Need ("configured worker digest");
            Deny_Post := Ada.Command_Line.Argument_Count >= 5 + Shift and then Ada.Command_Line.Argument (5 + Shift) = "deny-post";
            Stage.Prepare_Root (Root_Path, State_Path, Store_Path, Ada.Command_Line.Argument (3 + Shift),
               Expected, Worker, Deadline, Status);
            if Deny_Post then Expect (Status = Indeterminate, "post-extraction denial remains uncertain");
            else Need ("actual service extraction through stage admission"); end if;
            Expect (Prepare_Calls = 3 and then Post_Calls = 1, "pre and post admission ran under reservations");
            if Ada.Command_Line.Argument_Count >= 5 + Shift and then Ada.Command_Line.Argument (5 + Shift) = "reinspect" then
               Physical_Checks (Ada.Command_Line.Argument (3 + Shift), Worker);
            end if;
         end;
      end if;
      MC_FS.Open_Root (Root_Path, Stage_Root, Status, Private_Only => True); Need ("observe staged root");
      MC_FS.Open_Read (Stage_Root, "tree/root.tar", File, Status); Need ("actual staged tar");
      MC_FS.Hash (File, MC_Store.Max_Object_Size, Ignored, Until_Time, Status); Need ("actual staged tar hash");
      Expect (Ignored = Selected_Archive, "physical staged bytes equal assembled payload"); MC_FS.Close (File);
      MC_FS.Close (Stage_Root);
      MC_Store.Open (Store_Path, Store, Status); Need ("reopen root generation store");
      MC_Store.Check_Pin (Store, M.Transaction_ID, Expected, Status); Need ("existing generation pin binds root manifest");
      MC_Store.Close (Store); MC_FS.Open_Root (Store_Path, CAS, Status, Private_Only => True); Need ("private retained root fault");
      MC_FS.Rename (CAS, Object_Path (Root_Manifest), "held-generation-root", True, Status); Need ("hold root manifest");
      Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status);
      Expect (Status /= OK, "stage cannot pass with missing root manifest");
      MC_FS.Stat (CAS, Object_Path (Root_Manifest), Info, Status); Need ("observe missing root manifest");
      Expect (Info.Kind = MC_FS.Absent, "stage does not reconstruct missing retention evidence");
      MC_FS.Rename (CAS, "held-generation-root", Object_Path (Root_Manifest), True, Status); Need ("restore exact root manifest");
      MC_FS.Close (CAS);
      Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status); Need ("restored root generation inspection");
      if Configured then
         MC_FS.Open_Root (Store_Path, CAS, Status, Private_Only => True); Need ("configured retention fixture");
         for Missing of Digest_Array'(M.Configured_Root, M.Configuration_Closure) loop
            MC_FS.Rename (CAS, Object_Path (Missing), "held-configured-record", True, Status); Need ("hold configured record");
            Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status);
            Expect (Status /= OK, "stage refuses missing configured record or closure");
            MC_FS.Stat (CAS, Object_Path (Missing), Info, Status); Need ("inspect missing configured record");
            Expect (Info.Kind = MC_FS.Absent, "missing configured record is not reconstructed");
            MC_FS.Rename (CAS, "held-configured-record", Object_Path (Missing), True, Status); Need ("restore configured record");
         end loop;
         MC_FS.Close (CAS);
         Default_Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status);
         Expect (Status = Denied, "legacy inspection cannot qualify configured stage");
         Deny_Source := True; Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status);
         Expect (Status = Denied, "completed stage still needs current source admission"); Deny_Source := False;
         Ada.Text_IO.Put_Line ("CONFIGURED_STAGE_SOURCE_CALLS" & Natural'Image (Source_Calls));
      end if;
      MC_Store.Open (Store_Path, Store, Status); Need ("restore caller reservation"); Free (Plan); Free (Raw_Plan);
   exception when others => Closed := MC_Posix.Close (Foreign_Root); MC_FS.Close (File); MC_FS.Close (CAS); MC_FS.Close (Stage_Root); Free (Plan); Free (Raw_Plan); raise;
   end Run;
end Root_Archive_Stage_Test;
