-- SPDX-License-Identifier: BSD-3-Clause
-- Artificial signatures and exact fixture authorization; never a site provider.
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO; with Ada.Unchecked_Deallocation; with Interfaces.C; with System;
with MC_Codec; with MC_FS; with MC_Hex; with MC_Posix; with MC_SHA256; with MC_Text;
with Pkg_Archive_Supply; with Pkg_Supply_Map; with Pkg_Supply_Policy;
with Pkg_Deb_Final_Set; with Pkg_File_Plan; with Pkg_Generation_Descriptor;
with Pkg_Generation_Intent; with Pkg_Generation_Manifest; with Pkg_Generation_Stage;
with Test_Support; use Test_Support;
package body Root_Archive_Stage_Test with SPARK_Mode => Off is
   package GM renames Pkg_Generation_Manifest; package FP renames Pkg_File_Plan;
   use type Interfaces.C.int; use type Interfaces.C.unsigned_long_long; use type Byte;
   use type GM.Manifest; use type MC_FS.Entry_Kind;
   procedure Run (Store : in out MC_Store.Store; Store_Path : String;
      Catalog, Closure, Root_Manifest, Archive : Digest;
      Packages : Pkg_Selected_Catalog.Selection; Deadline : Counter) is
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
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Raw_Plan : Buffer_Access := new Bytes (1 .. FP.Max_Plan_Bytes);
      Wire, Changed : Bytes (1 .. GM.Max_Bytes); Used, Count : Natural;
      File : MC_FS.File; CAS, Stage_Root : MC_FS.Root; Info : MC_FS.Entry_Info;
      Parent : constant String := Ada.Directories.Containing_Directory (Store_Path);
      Root_Path : constant String := Parent & "/archive-stage-root";
      State_Path : constant String := Parent & "/archive-stage-state";
      Deny, Deny_Prepare, Deny_Post : Boolean := False;
      Prepare_Calls, Post_Calls : Natural := 0;
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
         if Phase in "stage:prepare-root" | "stage:root-prepared" then
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
         if Deny or else Manifest /= Expected or else Stage_ID /= M.Stage_ID or else Epoch /= M.Epoch
           or else Fence /= M.Fence or else Phase'Length <= 6 or else Phase (Phase'First .. Phase'First + 5) /= "stage:" then return; end if;
         if Plan = Zero_Digest then
            if Transaction_ID = M.Transaction_ID and then Evidence = Zero_Digest
              and then Phase in "stage:provision" | "stage:provision-root" | "stage:advance" |
                "stage:inspect" | "stage:inspect-batch" | "stage:inspected" |
                "stage:prepare-root" | "stage:root-prepared" then Status := OK; end if;
         elsif Plan = M.Batches (1).Plan and then Transaction_ID = GM.Transaction (M, 1)
           and then Evidence in Zero_Digest | Receipt then Status := OK; end if;
      end Authorize;
      package Stage is new Pkg_Generation_Stage (Authorize);
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
      MC_Store.Open_Object (Store, Archive, File, Status); Need ("assembled tar object");
      MC_FS.Info (File, Info, Status); Need ("assembled tar size"); MC_FS.Close (File);
      MC_Text.Set (Plan.Changes (3).Path, "tree/root.tar", Status); Need ("archive path");
      Plan.Changes (3).After := Plan.Changes (1).After; Plan.Changes (3).After.Content := Archive;
      Plan.Changes (3).After.Size := Info.Size;
      FP.Encode (Plan.all, Raw_Plan.all, Count, Status); Need ("root stage plan");
      MC_Store.Put (Store, Raw_Plan (1 .. Count), M.Batches (1).Plan, Status); Need ("retain stage plan");
      M.Batches (1).Receipt := Receipt;
      GM.Encode (M, Wire, Used, Status); Need ("root manifest encode");
      Expect (Used = 320 and then Wire (8) = 53 and then Wire (225 .. 256) = Root_Manifest, "v5 header exact");
      GM.Decode (Wire (1 .. Used), Decoded, Status); Need ("root manifest decode"); Expect (Decoded = M, "v5 round trip");
      for Tag in Byte range 49 .. 52 loop
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
      MC_Store.Put (Store, Wire (1 .. Used), Expected, Status); Need ("retained v5 manifest");
      Ada.Text_IO.Put_Line ("GENERATION_MANIFEST " & MC_Hex.Encode (Expected));
      MC_Store.Close (Store);
      Ada.Directories.Create_Directory (Root_Path); Ada.Directories.Create_Directory (State_Path);
      Deny := True; Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status);
      Expect (Status = Denied, "root archive stage still needs independent authorization"); Deny := False;
      Stage.Provision (Root_Path, State_Path, Store_Path, Wire (1 .. Used), Expected, Deadline, Status); Need ("provision v5 stage");
      Stage.Advance (Root_Path, State_Path, Store_Path, Expected, Count, Deadline, Status); Need ("materialize root archive stage");
      Expect (Count = 1, "one root archive batch");
      Stage.Inspect (Root_Path, State_Path, Store_Path, Expected, Deadline, Status); Need ("inspect exact root stage");
      Deny_Prepare := True;
      Stage.Prepare_Root (Root_Path, State_Path, Store_Path, "/nonexistent-preparation.sock",
         Expected, Receipt, Deadline, Status);
      Expect (Status = Denied and then Prepare_Calls = 1 and then Post_Calls = 0, "preparation requires its own live authorization");
      Deny_Prepare := False;
      if Ada.Command_Line.Argument_Count >= 4 then
         declare
            Worker : Digest;
         begin
            MC_Hex.Decode (Ada.Command_Line.Argument (4), Worker, Status); Need ("configured worker digest");
            Deny_Post := Ada.Command_Line.Argument_Count = 5 and then Ada.Command_Line.Argument (5) = "deny-post";
            Stage.Prepare_Root (Root_Path, State_Path, Store_Path, Ada.Command_Line.Argument (3),
               Expected, Worker, Deadline, Status);
            if Deny_Post then Expect (Status = Indeterminate, "post-extraction denial remains uncertain");
            else Need ("actual service extraction through stage admission"); end if;
            Expect (Prepare_Calls = 3 and then Post_Calls = 1, "pre and post admission ran under reservations");
         end;
      end if;
      MC_FS.Open_Root (Root_Path, Stage_Root, Status, Private_Only => True); Need ("observe staged root");
      MC_FS.Open_Read (Stage_Root, "tree/root.tar", File, Status); Need ("actual staged tar");
      MC_FS.Hash (File, MC_Store.Max_Object_Size, Ignored, Until_Time, Status); Need ("actual staged tar hash");
      Expect (Ignored = Archive, "physical staged bytes equal assembled payload"); MC_FS.Close (File);
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
      MC_Store.Open (Store_Path, Store, Status); Need ("restore caller reservation"); Free (Plan); Free (Raw_Plan);
   exception when others => MC_FS.Close (File); MC_FS.Close (CAS); MC_FS.Close (Stage_Root); Free (Plan); Free (Raw_Plan); raise;
   end Run;
end Root_Archive_Stage_Test;
