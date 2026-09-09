-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Strings.Unbounded; with Ada.Text_IO;
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_Deb_Metadata; with Pkg_Deb_Payload; with Pkg_Deb_Relations; with Pkg_Deb_Semantics;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
procedure Run_Selected_Catalog_Tests with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package X renames Pkg_Payload_Index;
   package P renames Pkg_Deb_Payload; package R renames Pkg_Deb_Relations;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned;
   use type C.Package_Record; use type R.Atom; use type Pkg_Deb_Semantics.Multi_Arch;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome; Now, Deadline : Counter;
   Value, Other : C.Catalog; Payload, Reverse_Payload, Partial_Payload : X.Index;
   Sources : array (1 .. 4) of P.Inventory;
   Selected, Reversed, Changed : C.Selection (1 .. 4);
   Names : constant array (1 .. 4) of Unbounded_String :=
     (To_Unbounded_String ("consumer.deb"), To_Unbounded_String ("library-amd64.deb"),
      To_Unbounded_String ("library-arm64.deb"), To_Unbounded_String ("empty.deb"));
   Item, Copy : C.Package_Record; Atom, Atom_Copy : R.Atom; Original, Hash : Digest;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Import (Name : String) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, F, Status); Need ("open " & Name);
      MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Original, Status); Need ("import"); MC_FS.Close (F);
   exception when others => MC_FS.Close (F); raise;
   end Import;
   procedure Hidden (Object : C.Catalog) is
   begin
      Expect (not C.Sealed (Object) and then C.Package_Count (Object) = 0
         and then C.Fingerprint (Object) = Zero_Digest and then C.Payload_Hash (Object) = Zero_Digest,
         "partial/failed candidate not published");
      C.Read_Package (Object, 1, Item, Status);
      Expect (Status = Invalid_Input and then Item.Original = Zero_Digest, "hidden identity reset");
      C.Read_Atom (Object, 1, R.Depends, 1, Atom, Status);
      Expect (Status = Invalid_Input and then MC_Text.Length (Atom.Name) = 0, "hidden relation reset");
      Expect (C.Atom_Count (Object, 1, R.Depends) = 0 and then C.Group_Count (Object, 1, R.Depends) = 0,
         "no partial relation counts");
   end Hidden;
   procedure Collect (Object : in out C.Catalog) is
   begin
      for S of Selected loop C.Add (Object, Store, S.Original, Deadline, Status); Need ("collect native metadata"); end loop;
   end Collect;
   procedure Print (Object : C.Catalog) is
      Tab : constant String := (1 => ASCII.HT);
      function N (Number : Natural) return String is (Natural'Image (Number));
   begin
      Ada.Text_IO.Put_Line ("CATALOG " & MC_Hex.Encode (C.Fingerprint (Object)));
      Ada.Text_IO.Put_Line ("PAYLOAD " & MC_Hex.Encode (C.Payload_Hash (Object)));
      for I in 1 .. C.Package_Count (Object) loop
         C.Read_Package (Object, I, Item, Status); Need ("print package");
         Ada.Text_IO.Put_Line ("PACKAGE" & Tab & MC_Hex.Encode (Item.Original) & Tab & MC_Hex.Encode (Item.Archive)
            & Tab & MC_Hex.Encode (Item.Control) & Tab & MC_Text.Image (Item.Identity.Name)
            & Tab & MC_Text.Image (Item.Identity.Version) & Tab & MC_Text.Image (Item.Identity.Architecture)
            & Tab & MC_Text.Image (Item.Identity.Source_Name) & Tab & MC_Text.Image (Item.Identity.Source_Version)
            & Tab & N (Pkg_Deb_Semantics.Multi_Arch'Pos (Item.Identity.Multi))
            & Tab & N (Boolean'Pos (Item.Identity.Essential)) & Tab & N (Boolean'Pos (Item.Identity.Protected_Package))
            & Tab & N (Boolean'Pos (Item.Identity.Has_Installed_Size)) & Tab & Counter'Image (Item.Identity.Installed_Size_KiB));
         for Kind in R.Field_Kind loop
            Ada.Text_IO.Put_Line ("FIELD" & Tab & MC_Hex.Encode (Item.Original) & Tab & R.Field_Name (Kind)
               & Tab & N (C.Atom_Count (Object, I, Kind)) & Tab & N (C.Group_Count (Object, I, Kind)));
            for J in 1 .. C.Atom_Count (Object, I, Kind) loop
               C.Read_Atom (Object, I, Kind, J, Atom, Status); Need ("print atom");
               Ada.Text_IO.Put_Line ("ATOM" & Tab & MC_Hex.Encode (Item.Original) & Tab & R.Field_Name (Kind)
                  & Tab & N (J) & Tab & N (Atom.Group_Number) & Tab & N (Pkg_Deb_Semantics.Relation'Pos (Atom.Operator))
                  & Tab & MC_Text.Image (Atom.Name) & Tab & MC_Text.Image (Atom.Architecture) & Tab & MC_Text.Image (Atom.Version));
            end loop;
         end loop;
      end loop;
   end Print;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 4, "CAS, media, optional list and --scan");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      C.Add (Value, Store, Zero_Digest, 0, Status); Expect (Status = Denied, "root Add refused");
      C.Seal (Value, Selected, Payload, 0, Status); Expect (Status = Denied, "root Seal refused"); Hidden (Value); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("source media");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 600_000;
   if Ada.Command_Line.Argument_Count = 4 then
      Expect (Ada.Command_Line.Argument (4) = "--scan", "exact scan option");
      declare
         List : Ada.Text_IO.File_Type; Name : String (1 .. 4096); Last, Count : Natural := 0;
         Scan_Set : C.Selection (1 .. C.Max_Packages);
         type Access_Observation is access Pkg_Deb_Metadata.Observation;
         procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Access_Observation);
         Observed : Access_Observation := new Pkg_Deb_Metadata.Observation;
      begin
         Ada.Text_IO.Open (List, Ada.Text_IO.In_File, Ada.Command_Line.Argument (3));
         while not Ada.Text_IO.End_Of_File (List) loop
            Ada.Text_IO.Get_Line (List, Name, Last); Expect (Last in 1 .. 4095 and then Count < C.Max_Packages, "bounded scan list");
            Import (Name (1 .. Last)); Count := Count + 1;
            Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status); Need ("scan metadata");
            Scan_Set (Count) := (Original, Observed.Control);
            P.Stage (Store, Original, Deadline, Sources (1), Status); Need ("scan payload");
            X.Add (Payload, Sources (1), Deadline, Status); Need ("scan claims"); P.Clear (Sources (1));
            C.Add (Value, Store, Original, Deadline, Status); Need ("scan candidate");
         end loop;
         Ada.Text_IO.Close (List); Free (Observed);
         X.Seal (Payload, Deadline, Status); Need ("scan index");
         C.Seal (Value, Scan_Set (1 .. Count), Payload, Deadline, Status); Need ("scan binding"); Print (Value);
      exception when others => Free (Observed); raise;
      end;
      MC_FS.Close (Media); MC_Store.Close (Store); Report; return;
   end if;
   Hidden (Value); C.Seal (Value, Selected, Payload, Deadline, Status); Expect (Status = Invalid_Input, "unobserved candidate refused");
   for I in Names'Range loop
      Import (To_String (Names (I))); Selected (I).Original := Original;
      declare
         type Access_Observation is access Pkg_Deb_Metadata.Observation;
         procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Access_Observation);
         Observed : Access_Observation := new Pkg_Deb_Metadata.Observation;
      begin
         Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status); Need ("independent expected control");
         Selected (I).Control := Observed.Control; Free (Observed);
      exception when others => Free (Observed); raise;
      end;
      P.Stage (Store, Original, Deadline, Sources (I), Status); Need ("source payload");
      X.Add (Payload, Sources (I), Deadline, Status); Need ("claim collection");
      C.Add (Value, Store, Original, Deadline, Status); Need ("native metadata collection"); Hidden (Value);
   end loop;
   X.Seal (Payload, Deadline, Status); Need ("all claim sources");
   C.Seal (Value, Selected, Payload, Deadline, Status); Need ("bind exact set");
   Expect (C.Package_Count (Value) = 4 and then C.Matches_Payload (Value, Payload), "selected metadata and claims bound");
   Hash := C.Fingerprint (Value); Print (Value);
   C.Seal (Value, Selected, Payload, Deadline, Status); Need ("repeated seal"); Expect (C.Fingerprint (Value) = Hash, "stable binding");
   for I in reverse Sources'Range loop
      X.Add (Reverse_Payload, Sources (I), Deadline, Status); Need ("reverse claims");
      C.Add (Other, Store, Selected (I).Original, Deadline, Status); Need ("reverse metadata");
      Reversed (5 - I) := Selected (I);
   end loop;
   X.Seal (Reverse_Payload, Deadline, Status); Need ("reverse index");
   C.Seal (Other, Reversed, Reverse_Payload, Deadline, Status); Need ("reverse binding");
   Expect (C.Fingerprint (Other) = Hash, "selection and observation order independent");
   for I in 1 .. C.Package_Count (Value) loop
      C.Read_Package (Value, I, Item, Status); Need ("package record");
      C.Read_Package (Other, I, Copy, Status); Need ("reverse package record"); Expect (Item = Copy, "all identity fields retained");
      for Kind in R.Field_Kind loop
         Expect (C.Atom_Count (Value, I, Kind) = C.Atom_Count (Other, I, Kind)
            and then C.Group_Count (Value, I, Kind) = C.Group_Count (Other, I, Kind), "all relationship groups stable");
         for J in 1 .. C.Atom_Count (Value, I, Kind) loop
            C.Read_Atom (Value, I, Kind, J, Atom, Status); Need ("relationship atom");
            C.Read_Atom (Other, I, Kind, J, Atom_Copy, Status); Need ("reverse atom"); Expect (Atom = Atom_Copy, "all atom fields stable");
         end loop;
      end loop;
      if MC_Text.Image (Item.Identity.Name) = "consumer" then
         Expect (C.Atom_Count (Value, I, R.Depends) = 3 and then C.Group_Count (Value, I, R.Depends) = 2, "alternatives not flattened");
         C.Read_Atom (Value, I, R.Provides, 1, Atom, Status); Need ("qualified provides retained");
         Expect (MC_Text.Image (Atom.Architecture) = "amd64" and then MC_Text.Image (Atom.Version) = "1.0", "no architecture or provided version omission");
         Expect (Item.Identity.Essential and then Item.Identity.Protected_Package and then Item.Identity.Has_Installed_Size
            and then Item.Identity.Installed_Size_KiB = 0 and then MC_Text.Image (Item.Identity.Source_Version) = "1:1.0-2", "flags and distinct source version");
      end if;
   end loop;
   C.Read_Package (Value, 5, Item, Status); Expect (Status = Invalid_Input and then Item.Original = Zero_Digest, "package bounds");
   C.Read_Atom (Value, 5, R.Depends, 1, Atom, Status); Expect (Status = Invalid_Input, "relation package bounds");
   C.Read_Atom (Value, 1, R.Depends, R.Max_Atoms + 1, Atom, Status); Expect (Status = Invalid_Input, "atom bounds");
   Changed := Selected; Changed (1).Control := Selected (2).Control;
   C.Seal (Other, Changed, Payload, Deadline, Status); Expect (Status = Conflict, "reseal checks expected control"); Hidden (Other);
   Collect (Other); Changed := Selected; Changed (4) := Selected (1);
   C.Seal (Other, Changed, Payload, Deadline, Status); Expect (Status = Conflict, "duplicate selected original cannot hide missing source"); Hidden (Other);
   Collect (Other); Changed := Selected; Changed (1).Original := Zero_Digest;
   C.Seal (Other, Changed, Payload, Deadline, Status); Expect (Status = Invalid_Input, "zero selected hash refused"); Hidden (Other);
   Collect (Other); C.Seal (Other, Selected (1 .. 3), Payload, Deadline, Status);
   Expect (Status = Conflict, "metadata extras cannot be dropped at seal"); Hidden (Other);
   for I in 1 .. 3 loop X.Add (Partial_Payload, Sources (I), Deadline, Status); Need ("partial source claims"); end loop;
   X.Seal (Partial_Payload, Deadline, Status); Need ("partial index"); Collect (Other);
   C.Seal (Other, Selected, Partial_Payload, Deadline, Status); Expect (Status = Conflict, "empty package missing from claims still rejected"); Hidden (Other);
   X.Clear (Partial_Payload);
   for I in 2 .. 4 loop X.Add (Partial_Payload, Sources (I), Deadline, Status); Need ("substitution index"); end loop;
   Import ("consumer-repacked.deb"); P.Stage (Store, Original, Deadline, Sources (1), Status); Need ("same control other original");
   X.Add (Partial_Payload, Sources (1), Deadline, Status); Need ("substitution source"); X.Seal (Partial_Payload, Deadline, Status); Need ("substitution seal");
   Collect (Other); C.Seal (Other, Selected, Partial_Payload, Deadline, Status);
   Expect (Status = Conflict, "equal counts and control cannot hide payload substitution"); Hidden (Other);
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Need ("duplicate identity baseline");
   C.Add (Other, Store, Original, Deadline, Status); Expect (Status = Conflict, "repacked same identity refused"); Hidden (Other);
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Need ("upgrade identity baseline"); Import ("consumer-upgrade.deb");
   C.Add (Other, Store, Original, Deadline, Status); Expect (Status = Conflict, "two versions of same name/architecture refused"); Hidden (Other);
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Need ("duplicate source baseline");
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Expect (Status = Conflict, "duplicate native original refused"); Hidden (Other);
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Need ("bad metadata baseline"); Import ("invalid.deb");
   C.Add (Other, Store, Original, Deadline, Status); Expect (Status = Invalid_Input, "bad control clears entire candidate"); Hidden (Other);
   Collect (Other); C.Seal (Other, Selected, Payload, 0, Status); Expect (Status = Stale, "expired seal clears candidate"); Hidden (Other);
   C.Add (Other, Store, Selected (1).Original, Deadline, Status); Need ("expiry baseline");
   C.Add (Other, Store, Selected (2).Original, 0, Status); Expect (Status = Stale, "expired addition clears candidate"); Hidden (Other);
   C.Add (Value, Store, Selected (1).Original, Deadline, Status); Expect (Status = Invalid_Input, "sealed candidate cannot append"); Hidden (Value);
   Collect (Value); C.Seal (Value, Reversed, Reverse_Payload, Deadline, Status); Need ("restart complete candidate");
   X.Clear (Payload); X.Clear (Reverse_Payload); for S of Sources loop P.Clear (S); end loop;
   Expect (C.Fingerprint (Value) = Hash and then C.Package_Count (Value) = 4
      and then not C.Matches_Payload (Value, Payload), "owned metadata stable; cleared external payload is not matching");
   C.Clear (Value); C.Clear (Value); Hidden (Value); MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Selected_Catalog_Tests;
