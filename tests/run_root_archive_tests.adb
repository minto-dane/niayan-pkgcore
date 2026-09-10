-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store;
with MC_Types; use MC_Types;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Deb_Metadata;
with Pkg_Deb_Payload; with Pkg_Payload_Index; with Pkg_Root_Archive;
with Root_Archive_Stage_Test; with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
procedure Run_Root_Archive_Tests with SPARK_Mode => Off is
   package A renames Pkg_Root_Archive; package C renames Pkg_Selected_Catalog;
   package X renames Pkg_Payload_Index; package P renames Pkg_Deb_Payload;
   use type Interfaces.C.unsigned; use type MC_FS.Entry_Kind; use type Byte;
   Store : MC_Store.Store; Media, CAS_Root : MC_FS.Root; Status : Outcome;
   Now, Deadline : Counter; Value : C.Catalog; Payload : X.Index; Source : P.Inventory;
   Packages : C.Selection (1 .. 3); Catalog, Closure, Manifest, Archive, Again, Other, Ownership : Digest;
   type Digest_Array is array (Positive range <>) of Digest;
   Limit : constant Counter := 1_048_576;
   procedure Need (Name : String) is
   begin Expect (Status = OK, Name & Outcome'Image (Status)); end Need;
   procedure Import (Name : String; Position : Positive) is
      File : MC_FS.File;
      type Observation_Access is access Pkg_Deb_Metadata.Observation;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
      Observed : Observation_Access := new Pkg_Deb_Metadata.Observation;
   begin
      MC_FS.Open_Read (Media, Name, File, Status); Need ("fixture open");
      MC_Store.Import_File (Store, File, Limit, Packages (Position).Original, Status); Need ("fixture import"); MC_FS.Close (File);
      Pkg_Deb_Metadata.Inspect (Store, Packages (Position).Original, Deadline, Observed.all, Status); Need ("original control");
      Packages (Position).Control := Observed.Control; Free (Observed);
      P.Stage (Store, Packages (Position).Original, Deadline, Source, Status); Need ("payload");
      X.Add (Payload, Source, Deadline, Status); Need ("payload index"); P.Clear (Source);
      C.Add (Value, Store, Packages (Position).Original, Deadline, Status); Need ("metadata");
   exception when others => MC_FS.Close (File); Free (Observed); raise;
   end Import;
   function Object_Path (Hash : Digest) return String is
      Hex : constant String := MC_Hex.Encode (Hash);
   begin return "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64); end Object_Path;
begin
   MC_Runtime.Initialize (Status); Need ("process hardening");
   if MC_Posix.Euid = 0 then
      A.Build (Store, Zero_Digest, Zero_Digest, (1 => 1), Limit, 0, Manifest, Archive, Status);
      Expect (Status = Denied and then Manifest = Zero_Digest and then Archive = Zero_Digest, "root build refused");
      A.Verify (Store, Zero_Digest, Limit, 0, Archive, Status);
      Expect (Status = Denied and then Archive = Zero_Digest, "root verify refused");
      A.Verify_Target (Store, Zero_Digest, Zero_Digest, Zero_Digest, Limit, 0, Archive, Status);
      Expect (Status = Denied and then Archive = Zero_Digest, "root bound verify refused");
      A.Verify_Ownership (Store, Zero_Digest, Zero_Digest, Zero_Digest, "amd64", Limit, 0, Archive, Ownership, Status);
      Expect (Status = Denied and then Archive = Zero_Digest and then Ownership = Zero_Digest, "root ownership verify refused"); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("media");
   MC_FS.Open_Root (Ada.Command_Line.Argument (1), CAS_Root, Status, Private_Only => True); Need ("private fault root");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 600_000;
   Import ("base.deb", 1); Import ("overlay.deb", 2); Import ("conflicting.deb", 3);
   X.Seal (Payload, Deadline, Status); Need ("source set");
   C.Seal (Value, Packages, Payload, Deadline, Status); Need ("native candidate");
   Pkg_Catalog_Store.Save (Store, Value, Deadline, Catalog, Status); Need ("catalog save");
   Pkg_Catalog_Retention.Prepare (Store, Catalog, Deadline, Closure, Status); Need ("retention closure");
   declare
      Chosen, Changed : A.Selection (1 .. X.Path_Count (Payload));
      High : A.Selection (Positive'Last - Chosen'Length + 1 .. Positive'Last);
      Cursor : Positive := 1; Claim : X.Claim; State : X.Path_State;
      Dir, File_Path, Root_Alternative, Dir_Alternative, File_Alternative, Dir_Conflict : Positive := 1;
      Info : MC_FS.Entry_Info;
      Wire, Modified : Bytes (1 .. A.Header_Size + 8 * Chosen'Length + 1) := (others => 0);
      Used : Natural;
      procedure Refuse (Label_Text : String; Picks : A.Selection; Max : Counter := Limit; Until_Time : Counter := Deadline) is
      begin
         A.Build (Store, Catalog, Closure, Picks, Max, Until_Time, Again, Other, Status);
         Expect (Status /= OK and then Again = Zero_Digest and then Other = Zero_Digest, Label_Text);
      end Refuse;
      procedure Reject_Wire (Data : Bytes; Label_Text : String) is
      begin
         MC_Store.Put (Store, Data, Again, Status); Need ("retain candidate manifest");
         A.Verify (Store, Again, Limit, Deadline, Other, Status);
         Expect (Status /= OK and then Other = Zero_Digest, Label_Text);
      end Reject_Wire;
   begin
      for I in Chosen'Range loop
         X.Read_Claim (Payload, Cursor, Claim, Status); Need ("path start");
         X.Inspect_Path (Payload, P.Byte_Strings.To_String (Claim.Item.Path), State, Status); Need ("path claims");
         Chosen (I) := State.First;
         for J in State.First .. State.Last loop
            X.Read_Claim (Payload, J, Claim, Status); Need ("choice");
            if Claim.Source.Original = Packages (1).Original then Chosen (I) := J; end if;
            declare Name : constant String := P.Byte_Strings.To_String (Claim.Item.Path); begin
               if Name = "" and then Claim.Source.Original = Packages (2).Original then Root_Alternative := J;
               elsif Name = "dir" then
                  Dir := I;
                  if Claim.Source.Original = Packages (2).Original then Dir_Alternative := J;
                  elsif Claim.Source.Original = Packages (3).Original then Dir_Conflict := J; end if;
               elsif Name = "dir/file" then
                  File_Path := I;
                  if Claim.Source.Original = Packages (2).Original then File_Alternative := J; end if;
               end if;
            end;
         end loop;
         Cursor := State.Last + 1;
      end loop;
      A.Build (Store, Catalog, Closure, Chosen, Limit, Deadline, Manifest, Archive, Status); Need ("assemble actual payload spans");
      A.Verify (Store, Manifest, Limit, Deadline, Again, Status); Need ("reobserve root archive"); Expect (Again = Archive, "archive identity");
      A.Verify_Target (Store, Manifest, Catalog, Closure, Limit, Deadline, Again, Status); Need ("enclosing target verification");
      Expect (Again = Archive, "target-linked root identity");
      A.Verify_Target (Store, Manifest, Archive, Closure, Limit, Deadline, Again, Status);
      Expect (Status = Conflict and then Again = Zero_Digest, "foreign catalog cannot carry this root");
      A.Verify_Target (Store, Manifest, Catalog, Archive, Limit, Deadline, Again, Status);
      Expect (Status = Conflict and then Again = Zero_Digest, "foreign closure cannot carry this root");
      A.Verify_Target (Store, Manifest, Zero_Digest, Closure, Limit, Deadline, Again, Status);
      Expect (Status = Invalid_Input and then Again = Zero_Digest, "enclosing catalog cannot be omitted");
      A.Verify_Ownership (Store, Manifest, Catalog, Closure, "amd64", Limit, Deadline, Again, Ownership, Status);
      Need ("retained logical ownership"); Expect (Again = Archive and then Ownership /= Zero_Digest, "owned root binding");
      High := Chosen;
      A.Build (Store, Catalog, Closure, High, Limit, Deadline, Again, Other, Status); Need ("highest array bound");
      Expect (Again = Manifest and then Other = Archive, "selection bounds do not alter bytes");
      Ada.Text_IO.Put_Line ("MANIFEST " & MC_Hex.Encode (Manifest));
      Ada.Text_IO.Put_Line ("ARCHIVE " & MC_Hex.Encode (Archive));
      for Position of Chosen loop
         X.Read_Claim (Payload, Position, Claim, Status); Need ("print choice");
         Ada.Text_IO.Put_Line ("CHOICE " & MC_Hex.Encode (Claim.Source.Original) & Positive'Image (Claim.Source_Position));
      end loop;
      Changed := Chosen; Changed (1) := Root_Alternative; Changed (Dir) := Dir_Alternative;
      A.Build (Store, Catalog, Closure, Changed, Limit, Deadline, Again, Other, Status); Need ("explicit shared directory owner");
      Expect (Again /= Manifest and then Other /= Archive, "owner attributes affect archive and manifest");
      A.Verify_Ownership (Store, Again, Catalog, Closure, "amd64", Limit, Deadline, Other, Ownership, Status);
      Expect (Status = Conflict and then Other = Zero_Digest and then Ownership = Zero_Digest, "structural candidate needs justified owners");
      Refuse ("missing path", Chosen (2 .. Chosen'Last));
      Changed := Chosen; Changed (1) := Chosen (2); Refuse ("duplicate path", Changed);
      Changed := Chosen; Changed (1) := Chosen (2); Changed (2) := Chosen (1); Refuse ("path order", Changed);
      Changed := Chosen; Changed (Dir) := Dir_Conflict; Refuse ("selected nondirectory ancestor", Changed);
      Changed := Chosen; Changed (File_Path) := File_Alternative; Refuse ("hardlink target from another original", Changed);
      Refuse ("bounded output", Chosen, Max => 1_024);
      Refuse ("expired build", Chosen, Until_Time => 0);
      Refuse ("infinite deadline", Chosen, Until_Time => Counter'Last);
      A.Verify (Store, Manifest, Limit, 0, Again, Status); Expect (Status = Stale and then Again = Zero_Digest, "expired verify");
      MC_Store.Read_Object (Store, Manifest, Wire, Used, Status); Need ("read manifest");
      Reject_Wire (Wire (1 .. 0), "empty manifest");
      Reject_Wire (Wire (1 .. Used - 1), "truncated manifest");
      Reject_Wire (Wire, "trailing manifest byte");
      Modified := Wire; Modified (8) := Character'Pos ('2'); Reject_Wire (Modified (1 .. Used), "unknown format");
      Modified := Wire; Modified (73) := Modified (73) xor 1; Reject_Wire (Modified (1 .. Used), "payload fingerprint binding");
      Modified := Wire; MC_Codec.Put64 (Modified, 137, 1_024); Reject_Wire (Modified (1 .. Used), "archive length binding");
      Modified := Wire; MC_Codec.Put64 (Modified, 145, 0); Reject_Wire (Modified (1 .. Used), "empty selection");
      Modified := Wire; MC_Codec.Put64 (Modified, 153, 0); Reject_Wire (Modified (1 .. Used), "zero claim index");
      Modified := Wire; Modified (105 .. 136) := Catalog; Reject_Wire (Modified (1 .. Used), "wrong archive");
      for Hash of Digest_Array'(Archive, Packages (1).Original) loop
         MC_FS.Rename (CAS_Root, Object_Path (Hash), "held-root-input", True, Status); Need ("hold required object");
         A.Verify (Store, Manifest, Limit, Deadline, Again, Status); Expect (Status /= OK and then Again = Zero_Digest, "missing object refusal");
         MC_FS.Stat (CAS_Root, Object_Path (Hash), Info, Status); Need ("observe missing object");
         Expect (Info.Kind = MC_FS.Absent, "verification does not recreate missing object");
         MC_FS.Rename (CAS_Root, "held-root-input", Object_Path (Hash), True, Status); Need ("explicit restoration");
      end loop;
      A.Verify (Store, Manifest, Limit, Deadline, Again, Status); Need ("verify after explicit restoration");
      Expect (Again = Archive, "restored archive unchanged");
   end;
   Root_Archive_Stage_Test.Run (Store, Ada.Command_Line.Argument (1), Catalog, Closure, Manifest, Archive, Packages, Deadline);
   MC_Store.Close (Store); MC_FS.Close (CAS_Root); MC_FS.Close (Media); Report;
exception when others => MC_Store.Close (Store); MC_FS.Close (CAS_Root); MC_FS.Close (Media); raise;
end Run_Root_Archive_Tests;
