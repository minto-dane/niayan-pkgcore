-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Strings.Unbounded; with Ada.Text_IO;
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_Catalog_Store; with Pkg_Deb_Metadata; with Pkg_Deb_Payload; with Pkg_Deb_Relations; with Pkg_Deb_Semantics;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
procedure Run_Catalog_Store_Tests with SPARK_Mode => Off is
   package IO renames Pkg_Catalog_Store; package C renames Pkg_Selected_Catalog;
   package X renames Pkg_Payload_Index; package P renames Pkg_Deb_Payload; package R renames Pkg_Deb_Relations;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned; use type Byte;
   use type C.Package_Record; use type R.Atom; use type X.Claim;
   Store : MC_Store.Store; Media, CAS_Root : MC_FS.Root; Status : Outcome; Now, Deadline : Counter := 0;
   Value, Loaded, Unsealed : C.Catalog; Payload, Restored : X.Index; Source : P.Inventory;
   Selected : C.Selection (1 .. 4);
   Names : constant array (1 .. 4) of Unbounded_String :=
     (To_Unbounded_String ("consumer.deb"), To_Unbounded_String ("library-amd64.deb"),
      To_Unbounded_String ("library-arm64.deb"), To_Unbounded_String ("empty.deb"));
   Item, Copy : C.Package_Record; Atom, Atom_Copy : R.Atom; Claim, Claim_Copy : X.Claim;
   Original, Address, Saved, Bad : Digest; Frame, Changed : Bytes (1 .. IO.Header_Size + 4 * IO.Entry_Size + 1);
   Used, Invalid_Cases : Natural := 0;
   Short_Lengths : constant array (1 .. 3) of Natural := (0, 15, 55);
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Import (Name : String) is
      File : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, File, Status); Need ("fixture open");
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Original, Status); Need ("fixture import"); MC_FS.Close (File);
   exception when others => MC_FS.Close (File); raise;
   end Import;
   procedure Hidden is
   begin
      Expect (not C.Sealed (Loaded) and then C.Package_Count (Loaded) = 0 and then C.Fingerprint (Loaded) = Zero_Digest
         and then not X.Sealed (Restored) and then X.Package_Count (Restored) = 0 and then X.Fingerprint (Restored) = Zero_Digest,
         "failure clears catalog and payload together");
      C.Read_Package (Loaded, 1, Copy, Status); Expect (Status = Invalid_Input and then Copy.Original = Zero_Digest, "failed catalog unreadable");
      X.Read_Claim (Restored, 1, Claim_Copy, Status); Expect (Status = Invalid_Input, "failed claims unreadable");
   end Hidden;
   procedure Restore is
   begin IO.Load (Store, Saved, Deadline, Loaded, Restored, Status); Need ("restore saved catalog"); end Restore;
   procedure Reject (Data : Bytes; Label_Text : String) is
   begin
      Restore; MC_Store.Put (Store, Data, Bad, Status); Need ("store test candidate");
      IO.Load (Store, Bad, Deadline, Loaded, Restored, Status);
      Ada.Text_IO.Put_Line ("REJECT " & Label_Text & " " & Outcome'Image (Status));
      Expect (Status /= OK, Label_Text); Hidden; Invalid_Cases := Invalid_Cases + 1;
   end Reject;
   function Object_Path (Hash : Digest) return String is
      Hex : constant String := MC_Hex.Encode (Hash);
   begin return "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64); end Object_Path;
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
   Expect (Ada.Command_Line.Argument_Count = 2, "fresh CAS and fixture directory");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      IO.Save (Store, Value, 0, Address, Status); Expect (Status = Denied and then Address = Zero_Digest, "root save refused");
      IO.Load (Store, Zero_Digest, 0, Loaded, Restored, Status); Expect (Status = Denied, "root load refused"); Hidden; Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("media");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 600_000;
   for I in Selected'Range loop
      Import (To_String (Names (I))); Selected (I).Original := Original;
      declare
         type Observation_Access is access Pkg_Deb_Metadata.Observation;
         procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
         Observed : Observation_Access := new Pkg_Deb_Metadata.Observation;
      begin
         Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status); Need ("original control");
         Selected (I).Control := Observed.Control; Free (Observed);
      exception when others => Free (Observed); raise;
      end;
      P.Stage (Store, Original, Deadline, Source, Status); Need ("payload");
      X.Add (Payload, Source, Deadline, Status); Need ("payload index"); P.Clear (Source);
      C.Add (Value, Store, Original, Deadline, Status); Need ("metadata");
   end loop;
   X.Seal (Payload, Deadline, Status); Need ("source set");
   C.Seal (Value, Selected, Payload, Deadline, Status); Need ("native candidate");
   IO.Save (Store, Value, Deadline, Saved, Status); Need ("persist canonical preimage");
   Expect (Saved = C.Fingerprint (Value), "saved ID equals existing fingerprint");
   IO.Save (Store, Value, Deadline, Address, Status); Need ("idempotent save"); Expect (Address = Saved, "same immutable object");
   MC_Store.Read_Object (Store, Saved, Frame, Used, Status); Need ("saved bytes");
   Expect (Used = Frame'Length - 1, "exact canonical frame size");
   MC_Store.Close (Store); MC_Store.Open (Ada.Command_Line.Argument (1), Store, Status); Need ("reopen persistent CAS");
   Restore; Print (Loaded);
   Expect (C.Fingerprint (Loaded) = Saved and then C.Matches_Payload (Loaded, Restored)
      and then X.Fingerprint (Restored) = X.Fingerprint (Payload), "persistent metadata and claims binding");
   for I in 1 .. C.Package_Count (Value) loop
      C.Read_Package (Value, I, Item, Status); Need ("initial identity");
      C.Read_Package (Loaded, I, Copy, Status); Need ("loaded identity"); Expect (Item = Copy, "all identity fields retained");
      for Kind in R.Field_Kind loop
         Expect (C.Atom_Count (Value, I, Kind) = C.Atom_Count (Loaded, I, Kind)
            and then C.Group_Count (Value, I, Kind) = C.Group_Count (Loaded, I, Kind), "relation counts retained");
         for J in 1 .. C.Atom_Count (Value, I, Kind) loop
            C.Read_Atom (Value, I, Kind, J, Atom, Status); Need ("original atom");
            C.Read_Atom (Loaded, I, Kind, J, Atom_Copy, Status); Need ("loaded atom"); Expect (Atom = Atom_Copy, "full atom retained");
         end loop;
      end loop;
   end loop;
   Expect (X.Claim_Count (Payload) = X.Claim_Count (Restored), "all claims retained");
   for I in 1 .. X.Claim_Count (Payload) loop
      X.Read_Claim (Payload, I, Claim, Status); Need ("initial claim");
      X.Read_Claim (Restored, I, Claim_Copy, Status); Need ("loaded claim"); Expect (Claim = Claim_Copy, "full claim retained");
   end loop;
   IO.Save (Store, Value, 0, Address, Status); Expect (Status = Stale and then Address = Zero_Digest, "expired save clears old address");
   Expect (C.Fingerprint (Value) = Saved, "failed save preserves input");
   IO.Save (Store, Unsealed, Deadline, Address, Status); Expect (Status = Invalid_Input and then Address = Zero_Digest, "unsealed save refused");
   IO.Load (Store, Saved, 0, Loaded, Restored, Status); Expect (Status = Stale, "expired load"); Hidden;
   Restore; IO.Load (Store, Zero_Digest, Deadline, Loaded, Restored, Status); Expect (Status = Invalid_Input, "zero address"); Hidden;
   for Size of Short_Lengths loop Reject (Frame (1 .. Size), "short-header"); end loop;
   Reject (Frame (1 .. Used - 1), "truncated-entry"); Reject (Frame, "trailing-byte");
   Changed := Frame; MC_Codec.Put64 (Changed, 1, 7); Reject (Changed (1 .. Used), "tag-length");
   Changed := Frame; Changed (16) := Character'Pos ('2'); Reject (Changed (1 .. Used), "unknown-version");
   Changed := Frame; MC_Codec.Put64 (Changed, 49, 0); Reject (Changed (1 .. Used), "empty-count");
   MC_Codec.Put64 (Changed, 49, Wide (C.Max_Packages + 1)); Reject (Changed (1 .. Used), "count-cap");
   MC_Codec.Put64 (Changed, 49, 3); Reject (Changed (1 .. Used), "count-length");
   Changed := Frame; Changed (17 .. 48) := Zero_Digest; Reject (Changed (1 .. Used), "zero-payload");
   Changed := Frame; Changed (17) := Changed (17) xor 1; Reject (Changed (1 .. Used), "wrong-payload");
   for Offset in 0 .. 2 loop
      Changed := Frame; Changed (57 + Offset * 32 .. 88 + Offset * 32) := Zero_Digest;
      Reject (Changed (1 .. Used), "zero-entry-digest");
   end loop;
   Changed := Frame; Changed (57 .. 152) := Frame (153 .. 248); Changed (153 .. 248) := Frame (57 .. 152);
   Reject (Changed (1 .. Used), "source-order");
   Changed := Frame; Changed (153 .. 248) := Frame (57 .. 152); Reject (Changed (1 .. Used), "duplicate-original");
   Changed := Frame; Changed (89) := Changed (89) xor 1; Reject (Changed (1 .. Used), "wrong-control-archive");
   Changed := Frame; Changed (121) := Changed (121) xor 1; Reject (Changed (1 .. Used), "wrong-raw-control");
   declare Oversize : constant Bytes (1 .. IO.Max_Bytes + 1) := (others => 0); begin Reject (Oversize, "object-cap"); end;
   Restore; MC_FS.Open_Root (Ada.Command_Line.Argument (1), CAS_Root, Status, Private_Only => True); Need ("private fault root");
   MC_FS.Rename (CAS_Root, Object_Path (Selected (4).Original), "held-original", True, Status); Need ("temporarily unavailable empty original");
   IO.Load (Store, Saved, Deadline, Loaded, Restored, Status); Expect (Status /= OK, "metadata cache cannot replace missing original"); Hidden;
   MC_FS.Rename (CAS_Root, "held-original", Object_Path (Selected (4).Original), True, Status); Need ("restore exact original"); Restore;
   MC_FS.Rename (CAS_Root, Object_Path (Saved), "held-catalog", True, Status); Need ("temporarily unavailable catalog");
   IO.Load (Store, Saved, Deadline, Loaded, Restored, Status); Expect (Status /= OK, "missing catalog is not empty state"); Hidden;
   MC_FS.Rename (CAS_Root, "held-catalog", Object_Path (Saved), True, Status); Need ("restore exact catalog"); Restore;
   C.Clear (Value); X.Clear (Payload); Expect (C.Fingerprint (Loaded) = Saved and then C.Matches_Payload (Loaded, Restored), "independent loaded lifetime");
   Expect (Invalid_Cases = 20, "complete malformed frame matrix");
   Ada.Text_IO.Put_Line ("STORED " & MC_Hex.Encode (Saved) & Natural'Image (Used));
   MC_FS.Close (CAS_Root); MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (CAS_Root); MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Catalog_Store_Tests;
