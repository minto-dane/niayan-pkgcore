-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Types; use MC_Types;
with Ada.Text_IO; with MC_Hex; with Pkg_Configured_Root;
with MC_Clock; with MC_FS; with MC_Posix; with MC_Runtime; with MC_Store;
with Pkg_Conffile_Choice; with Pkg_Conffile_Transition; with Pkg_Root_Configuration;
with Pkg_Root_Archive; with Pkg_Catalog_Store; with Pkg_Catalog_Retention;
with Pkg_Selected_Catalog; with Pkg_Deb_Metadata; with Pkg_Deb_Payload; with Pkg_Payload_Index;
with Test_Support; use Test_Support;
procedure Run_Root_Configuration_Tests with SPARK_Mode => Off is
   package C renames Pkg_Conffile_Choice; package T renames Pkg_Conffile_Transition;
   package R renames Pkg_Root_Configuration; package A renames Pkg_Root_Archive;
   package P renames Pkg_Deb_Payload; package X renames Pkg_Payload_Index;
   package S renames Pkg_Selected_Catalog;
   use type Interfaces.C.int; use type Interfaces.C.long; use type C.Attribute_Source;
   Store : MC_Store.Store; Media : MC_FS.Root; File : MC_FS.File;
   Root : MC_Posix.FD := -1; Ignored : Interfaces.C.int; Status : Outcome; Deadline : Counter;
   Proposal : R.Proposal_Access := new C.Proposal;
   procedure Free is new Ada.Unchecked_Deallocation (C.Proposal, R.Proposal_Access);
   Layout : R.Layout; Item : R.Entry_Reference; Retained : R.Choice_Binding;
   Selected : R.Choices (1 .. 1); Scope : C.Scope;
   Prior, Incoming, Catalog, Closure, Manifest, Archive, Decision, Kept : Digest;
   Context : constant Digest := (others => 3);
   Path : constant String := "/etc/fixture.conf"; Backup : constant String := "/etc/fixture.conf.save";
   Limit : constant Counter := 1_048_576;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Load (Name : String; Result : out Digest) is
   begin
      MC_FS.Open_Read (Media, Name & ".deb", File, Status); Need ("fixture open");
      MC_Store.Import_File (Store, File, Limit, Result, Status); MC_FS.Close (File); Need ("fixture retained");
   end Load;
   procedure Base (Name : String) is
      Candidate : S.Catalog; Payload : X.Index; Source : P.Inventory;
      Packages : S.Selection (1 .. 1);
      type Observation_Access is access Pkg_Deb_Metadata.Observation;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
      Observed : Observation_Access := new Pkg_Deb_Metadata.Observation;
   begin
      Load (Name, Incoming); Packages (1).Original := Incoming;
      Pkg_Deb_Metadata.Inspect (Store, Incoming, Deadline, Observed.all, Status); Need ("metadata");
      Packages (1).Control := Observed.Control; Free (Observed);
      P.Stage (Store, Incoming, Deadline, Source, Status); Need ("payload");
      X.Add (Payload, Source, Deadline, Status); Need ("index add"); X.Seal (Payload, Deadline, Status); Need ("index seal");
      S.Add (Candidate, Store, Incoming, Deadline, Status); Need ("catalog add");
      S.Seal (Candidate, Packages, Payload, Deadline, Status); Need ("catalog seal");
      Pkg_Catalog_Store.Save (Store, Candidate, Deadline, Catalog, Status); Need ("catalog save");
      Pkg_Catalog_Retention.Prepare (Store, Catalog, Deadline, Closure, Status); Need ("catalog retention");
      declare Picks : A.Selection (1 .. X.Path_Count (Payload)); begin
         for I in Picks'Range loop Picks (I) := I; end loop;
         A.Build (Store, Catalog, Closure, Picks, Limit, Deadline, Manifest, Archive, Status); Need ("real base root archive");
      end;
   exception when others => Free (Observed); raise;
   end Base;
   procedure Choose (Selection : T.Choice := T.Keep_Local; Destination : String := Backup;
      Prior_Source : Digest := Prior; Incoming_Source : Digest := Incoming) is
   begin
      C.Prepare (Store, Integer (Root), (others => 1), (others => 2), Context, C.Update,
         Path, Prior_Source, Incoming_Source, Limit, Deadline, Proposal.all, Status); Need ("real configuration proposal");
      C.Resolve (Store, Proposal.all, C.Address (Proposal.all), Selection, Destination, Deadline, Decision, Kept, Status); Need ("resolved choice");
      Selected (1) := (Proposal, Decision, Kept);
   end Choose;
   procedure Project (Refs : R.Choices; Intent : Digest := Context; Until_Time : Counter := Deadline) is
   begin
      R.Prepare (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Intent,
         "amd64", Refs, Limit, Until_Time, Layout, Status);
   end Project;
   procedure Rejected (Label_Text : String; Reason : Outcome := Conflict) is
   begin Expect (Status = Reason and then R.Count (Layout) = 0 and then R.Binding (Layout).Manifest = Zero_Digest, Label_Text & Outcome'Image (Status)); end Rejected;
   procedure Check_Entry (Position : Positive; Name : String; Kind : C.Attribute_Source := C.No_File) is
   begin
      R.Read_Entry (Layout, Position, Item, Status); Need ("read final entry");
      Expect (P.Byte_Strings.To_String (Item.Path) = Name, "canonical final path order");
      Expect (Item.Configuration.Source = Kind and then (Item.Base_Claim /= 0) = (Kind = C.No_File), "exact base or configuration source");
   end Check_Entry;
   procedure Serialize (Label_Text : String; Verify_Again : Boolean := False) is
      Record_ID, Root_ID, Retained_ID, Again : Digest;
   begin
      Pkg_Configured_Root.Build (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Context,
         "amd64", Selected, Limit, Deadline, Record_ID, Root_ID, Retained_ID, Status); Need ("configured full root " & Label_Text);
      Expect (Record_ID /= Zero_Digest and then Root_ID /= Zero_Digest and then Retained_ID /= Zero_Digest, "complete configured result");
      Ada.Text_IO.Put_Line ("CONFIGURED " & Label_Text & " " & MC_Hex.Encode (Record_ID) & " " & MC_Hex.Encode (Root_ID)
         & " " & MC_Hex.Encode (Retained_ID));
      if Verify_Again then
         Pkg_Configured_Root.Verify (Store, Record_ID, Retained_ID, Manifest, Catalog, Closure, (others => 1), (others => 2),
            Context, "amd64", Selected, Limit, Deadline, Again, Status); Need ("exact configured verification");
         Expect (Again = Root_ID, "deterministic configured root identity");
         Pkg_Configured_Root.Verify (Store, Record_ID, Retained_ID, Manifest, Catalog, Closure, (others => 1), (others => 2),
            (others => 9), "amd64", Selected, Limit, Deadline, Again, Status);
         Expect (Status = Conflict and then Again = Zero_Digest, "foreign configured context refused");
         declare Private_CAS : MC_FS.Root; Missing_File : MC_FS.File;
            Before_Record : constant Digest := Record_ID; Before_Root : constant Digest := Root_ID;
            Before_Retained : constant Digest := Retained_ID;
            H : constant String := MC_Hex.Encode (Root_ID);
         begin
            MC_FS.Open_Root (Ada.Command_Line.Argument (1), Private_CAS, Status); Need ("private configured output fault");
            MC_FS.Remove (Private_CAS, "objects/" & H (1 .. 2) & "/" & H (3 .. 64), False, Status);
            MC_FS.Close (Private_CAS); Need ("remove only generated root");
            Pkg_Configured_Root.Verify (Store, Record_ID, Retained_ID, Manifest, Catalog, Closure, (others => 1), (others => 2),
               Context, "amd64", Selected, Limit, Deadline, Again, Status);
            Expect (Status /= OK and then Again = Zero_Digest, "lost configured output not silently repaired");
            MC_Store.Open_Object (Store, Root_ID, Missing_File, Status); MC_FS.Close (Missing_File);
            Expect (Status /= OK, "verification left missing output absent");
            Pkg_Configured_Root.Build (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Context,
               "amd64", Selected, Limit, Deadline, Record_ID, Root_ID, Retained_ID, Status); Need ("explicit rebuild after isolated loss");
            Expect (Record_ID = Before_Record and then Root_ID = Before_Root and then Retained_ID = Before_Retained,
               "explicit rebuild keeps exact saved identities");
            Pkg_Configured_Root.Build (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Context,
               "amd64", Selected, 4_096, Deadline, Record_ID, Root_ID, Retained_ID, Status);
            Expect (Status = Exhausted and then Record_ID = Zero_Digest and then Root_ID = Zero_Digest and then Retained_ID = Zero_Digest,
               "configured total capacity includes headers and padding");
         end;
         Pkg_Configured_Root.Build (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Context,
            "amd64", Selected, Limit, 0, Record_ID, Root_ID, Retained_ID, Status);
         Expect (Status = Stale and then Record_ID = Zero_Digest and then Root_ID = Zero_Digest and then Retained_ID = Zero_Digest,
            "expired configured output cleared");
      end if;
   end Serialize;
begin
   Expect (Ada.Command_Line.Argument_Count = 3, "store root and media");
   MC_Runtime.Initialize (Status); Need ("runtime"); MC_Clock.Boottime_Milliseconds (Deadline, Status); Need ("clock"); Deadline := Deadline + 600_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("CAS");
   MC_FS.Open_Root (Ada.Command_Line.Argument (3), Media, Status); Need ("media");
   declare N : aliased constant String := Ada.Command_Line.Argument (2) & ASCII.NUL;
      E : aliased constant String := "etc" & ASCII.NUL; F : aliased constant String := "etc/fixture.conf" & ASCII.NUL;
      Text : aliased constant String := "local"; FD : MC_Posix.FD;
   begin
      Root := MC_Posix.Open (N'Address, MC_Posix.O_PATH + MC_Posix.O_DIRECTORY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
      Expect (Root >= 0, "private root"); Expect (MC_Posix.Mkdirat (Root, E'Address, 8#700#) = 0, "private parent");
      FD := MC_Posix.Openat (Root, F'Address, MC_Posix.O_RDWR + MC_Posix.O_CREAT + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 8#600#);
      Expect (FD >= 0, "private local file"); Expect (MC_Posix.Write (FD, Text'Address, Text'Length) = Text'Length, "local content"); Ignored := MC_Posix.Close (FD);
   end;
   Load ("normal", Prior); Base ("layout"); Choose;
   Project (Selected); Need ("configuration projected into root"); Expect (R.Count (Layout) = 4, "base plus local and backup");
   Expect (R.Binding (Layout).Manifest = Manifest and then R.Binding (Layout).Catalog = Catalog
      and then R.Binding (Layout).Closure = Closure and then R.Binding (Layout).Archive = Archive
      and then R.Binding (Layout).Ownership /= Zero_Digest and then R.Binding (Layout).Context = Context, "exact enclosing root inputs retained");
   Check_Entry (1, ""); Check_Entry (2, "etc"); Check_Entry (3, "etc/fixture.conf", C.Local_Observation);
   Expect (Item.Decision = Decision and then Item.Retained_Closure = Kept, "configuration retains its exact decision and closure");
   Expect (Item.Configuration.Object /= Zero_Digest, "full local metadata retained");
   Check_Entry (4, "etc/fixture.conf.save", C.Vendor_Payload);
   Expect (Item.Configuration.Object = Incoming and then P.Byte_Strings.To_String (Item.Configuration.Source_Path) = Path, "backup retains full original and source name");
   R.Read_Entry (Layout, 5, Item, Status); Expect (Status = Invalid_Input and then Item.Base_Claim = 0 and then P.Byte_Strings.Length (Item.Path) = 0, "no partial entry on invalid index");
   Serialize ("keep", True);
   Project ((1 .. 0 => <>)); Rejected ("unresolved declaration cannot fall back to packaged bytes");
   Project (Selected, Intent => (others => 9)); Rejected ("foreign intent rejected");
   Project ((1 => Selected (1), 2 => Selected (1))); Rejected ("duplicate configuration rejected");
   Choose (T.Use_Vendor); Project (Selected); Need ("vendor replacement projected");
   Check_Entry (3, "etc/fixture.conf", C.Vendor_Payload); Check_Entry (4, "etc/fixture.conf.save", C.Local_Observation);
   Serialize ("vendor");
   Base ("layout-stream"); Choose; Serialize ("links");
   Base ("layout");
   Choose (Destination => "/missing/save"); Project (Selected); Rejected ("missing final backup parent rejected");
   Choose; Project (Selected, Until_Time => 0); Rejected ("expired configuration projection", Stale);
   Base ("layout-collision"); Choose; Project (Selected); Rejected ("backup cannot overwrite a packaged path");
   Choose (Destination => Backup & "/child"); Project (Selected); Rejected ("backup parent cannot be a packaged regular file");
   Base ("layout-linked"); Choose; Project (Selected); Rejected ("hardlink dependency needs explicit inode effects", Unsupported);
   Base ("layout"); Choose (Incoming_Source => Prior, Selection => T.Unresolved, Destination => "");
   Project (Selected); Rejected ("foreign incoming original cannot configure catalog");
   Choose;
   declare N : aliased constant String := "etc/fixture.conf" & ASCII.NUL; FD : MC_Posix.FD; begin
      FD := MC_Posix.Openat (Root, N'Address, MC_Posix.O_RDONLY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
      Expect (FD >= 0, "open local change fixture"); Expect (MC_Posix.Fchmod (FD, 8#640#) = 0, "change local permission"); Ignored := MC_Posix.Close (FD);
   end;
   Project (Selected); Rejected ("late local change invalidates complete layout", Stale);
   C.Read_Scope (Store, Proposal.all, Decision, Kept, Deadline, Scope, Status);
   Expect (Status = Invalid_Input and then Scope.Root_ID = Zero_Identity and then Scope.Context = Zero_Digest, "invalid scope output cleared");
   Choose;
   declare N : aliased constant String := "etc/fixture.conf" & ASCII.NUL; FD : MC_Posix.FD;
      Record_ID, Root_ID, Retained_ID : Digest;
   begin
      FD := MC_Posix.Openat (Root, N'Address, MC_Posix.O_RDONLY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
      Expect (FD >= 0 and then MC_Posix.Fchmod (FD, 8#600#) = 0, "change permission after configured choice");
      Ignored := MC_Posix.Close (FD);
      Pkg_Configured_Root.Build (Store, Manifest, Catalog, Closure, (others => 1), (others => 2), Context,
         "amd64", Selected, Limit, Deadline, Record_ID, Root_ID, Retained_ID, Status);
      Expect (Status = Stale and then Record_ID = Zero_Digest and then Root_ID = Zero_Digest and then Retained_ID = Zero_Digest,
         "live changed source refuses entire configured root");
   end;
   declare N : aliased constant String := "etc/fixture.conf" & ASCII.NUL; begin
      Expect (MC_Posix.Unlinkat (Root, N'Address, 0) = 0, "delete private local setting");
   end;
   Choose; Project (Selected); Need ("keep local deletion projected"); Expect (R.Count (Layout) = 3, "deleted target excluded from final namespace");
   Expect (R.Choice_Count (Layout) = 1, "deleted target decision remains retained");
   R.Read_Choice (Layout, 1, Retained, Status); Need ("read deleted target choice");
   Expect (Retained.Proposal = C.Address (Proposal.all) and then Retained.Decision = Decision
      and then Retained.Closure = Kept and then P.Byte_Strings.To_String (Retained.Path) = Path, "exact deleted target references");
   Check_Entry (1, ""); Check_Entry (2, "etc"); Check_Entry (3, "etc/fixture.conf.save", C.Vendor_Payload);
   Serialize ("deleted");
   Choose (T.Use_Vendor, ""); Project (Selected); Need ("restore deleted setting from vendor"); Expect (R.Count (Layout) = 3, "restore requires no local backup");
   Check_Entry (3, "etc/fixture.conf", C.Vendor_Payload);
   Serialize ("restored");
   declare N : aliased constant String := "etc/fixture.conf" & ASCII.NUL; FD : MC_Posix.FD; begin
      FD := MC_Posix.Openat (Root, N'Address, MC_Posix.O_WRONLY + MC_Posix.O_CREAT + MC_Posix.O_EXCL + MC_Posix.O_CLOEXEC, 8#600#);
      Expect (FD >= 0, "empty regular local configuration"); Ignored := MC_Posix.Close (FD);
   end;
   Choose; Serialize ("empty");
   R.Clear (Layout); Free (Proposal); Ignored := MC_Posix.Close (Root); Root := -1;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => R.Clear (Layout); Free (Proposal); Ignored := MC_Posix.Close (Root); MC_FS.Close (File); MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Root_Configuration_Tests;
