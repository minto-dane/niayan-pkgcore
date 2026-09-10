-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store;
with MC_Types; use MC_Types;
with Pkg_Deb_Metadata; with Pkg_Deb_Payload; with Pkg_Payload_Index; with Pkg_Selected_Catalog;
with Pkg_Payload_Ownership; with Pkg_Root_Archive; with Test_Support; use Test_Support;
procedure Run_Payload_Ownership_Tests with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package X renames Pkg_Payload_Index;
   package P renames Pkg_Deb_Payload; package O renames Pkg_Payload_Ownership;
   use type Interfaces.C.unsigned; use type O.Failure_Kind;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome; Now, Deadline : Counter;
   Catalog : C.Catalog; Payload : X.Index; Binding : Digest; Issue : O.Finding;
   procedure Need (Name : String) is
   begin Expect (Status = OK, Name & Outcome'Image (Status)); end Need;
   procedure Scenario (First, Second : String; Accepted : Boolean; Reverse_Choice : Boolean := False) is
      Source : P.Inventory; Items : C.Selection (1 .. 2); File : MC_FS.File;
      type Metadata_Access is access Pkg_Deb_Metadata.Observation;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Metadata_Access);
      Metadata : Metadata_Access := new Pkg_Deb_Metadata.Observation;
      procedure Import (Name : String; Index : Positive) is
      begin
         MC_FS.Open_Read (Media, Name & ".deb", File, Status); Need ("fixture read");
         MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Items (Index).Original, Status); Need ("original retention"); MC_FS.Close (File);
         Pkg_Deb_Metadata.Inspect (Store, Items (Index).Original, Deadline, Metadata.all, Status); Need ("original metadata");
         Items (Index).Control := Metadata.Control;
         P.Stage (Store, Items (Index).Original, Deadline, Source, Status); Need ("payload observation");
         X.Add (Payload, Source, Deadline, Status); Need ("payload collection"); P.Clear (Source);
         C.Add (Catalog, Store, Items (Index).Original, Deadline, Status); Need ("native metadata collection");
      end Import;
   begin
      C.Clear (Catalog); X.Clear (Payload); Import (First, 1); Import (Second, 2); Free (Metadata);
      X.Seal (Payload, Deadline, Status); Need ("source seal"); C.Seal (Catalog, Items, Payload, Deadline, Status); Need ("catalog seal");
      declare
         Chosen : Pkg_Root_Archive.Selection (1 .. X.Path_Count (Payload));
         High : Pkg_Root_Archive.Selection (Positive'Last - Chosen'Length + 1 .. Positive'Last);
         Cursor : Positive := 1; Claim : X.Claim; State : X.Path_State; Saved : Digest;
      begin
         for I in Chosen'Range loop
            X.Read_Claim (Payload, Cursor, Claim, Status); Need ("path claim");
            X.Inspect_Path (Payload, P.Byte_Strings.To_String (Claim.Item.Path), State, Status); Need ("path group");
            Chosen (I) := State.First;
            for J in State.First .. State.Last loop
               X.Read_Claim (Payload, J, Claim, Status); Need ("owner candidate");
               if Claim.Source.Original = Items ((if Reverse_Choice then 1 else 2)).Original then Chosen (I) := J; end if;
            end loop;
            Cursor := State.Last + 1;
         end loop;
         O.Check (Catalog, Payload, Chosen, "amd64", Deadline, Binding, Issue, Status);
         Ada.Text_IO.Put_Line ("OWNERSHIP " & First & " " & Second & Boolean'Image (Reverse_Choice) & " " & Outcome'Image (Status)
            & " " & O.Failure_Kind'Image (Issue.Kind) & " " & MC_Hex.Encode (Binding));
         if Accepted then
            Need ("expected logical owners"); Expect (Binding /= Zero_Digest and then Issue.Kind = O.None, "complete ownership binding");
            Saved := Binding; High := Chosen;
            O.Check (Catalog, Payload, High, "amd64", Deadline, Binding, Issue, Status); Need ("highest selection bounds");
            Expect (Binding = Saved, "bounds preserve binding");
            O.Check (Catalog, Payload, Chosen, "arm64", Deadline, Binding, Issue, Status); Need ("other valid native policy");
            Expect (Binding /= Saved, "native architecture bound");
         else
            Expect (Status = Conflict and then Binding = Zero_Digest and then Issue.Kind /= O.None, "unjustified owner refused");
         end if;
         O.Check (Catalog, Payload, Chosen, "amd64", 0, Binding, Issue, Status);
         Expect (Status = Stale and then Binding = Zero_Digest, "expired ownership result cleared");
         O.Check (Catalog, Payload, Chosen, "amd64", Counter'Last, Binding, Issue, Status);
         Expect (Status = Invalid_Input and then Binding = Zero_Digest, "finite ownership deadline required");
         Chosen (1) := Chosen (Chosen'Last);
         O.Check (Catalog, Payload, Chosen, "amd64", Deadline, Binding, Issue, Status);
         Expect (Status = Conflict and then Binding = Zero_Digest, "selection must cover each path exactly once");
      end;
   exception when others => MC_FS.Close (File); Free (Metadata); raise;
   end Scenario;
begin
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      O.Check (Catalog, Payload, (1 => 1), "amd64", 0, Binding, Issue, Status);
      Expect (Status = Denied and then Binding = Zero_Digest, "root ownership checker refused"); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture media");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 600_000;
   Scenario ("victim", "takeover", True); Scenario ("victim", "takeover", False, True);
   Scenario ("victim", "unjustified", False); Scenario ("victim", "virtual", False);
   Scenario ("victim", "version", False); Scenario ("victim", "arch-match", True); Scenario ("victim", "arch-miss", False);
   Scenario ("same-amd64", "same-arm64", True); Scenario ("same-amd64", "different-arm64", False);
   Scenario ("same-amd64", "mode-arm64", False);
   MC_Store.Close (Store); MC_FS.Close (Media); Report;
exception when others => MC_Store.Close (Store); MC_FS.Close (Media); raise;
end Run_Payload_Ownership_Tests;
