-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Text_IO; with Ada.Directories; with Interfaces.C;
with MC_FS; with MC_Hex; with MC_Posix;
with Pkg_Configuration_Entry; with Pkg_Conffile_Choice; with Pkg_Conffile_Observation;
with Pkg_Conffile_Snapshot; with Pkg_Deb_Payload; with Pkg_Tar_Framing;
with Test_Support; use Test_Support;
package body Configuration_Entry_Test is
   package C renames Pkg_Conffile_Choice; package O renames Pkg_Conffile_Observation;
   package S renames Pkg_Conffile_Snapshot; package P renames Pkg_Deb_Payload;
   use type Word; use type Byte; use type Interfaces.C.int; use type Interfaces.C.long;
   procedure Run (Store : in out MC_Store.Store; Root_FD : Integer;
      Observation : Digest; Path, Media_Path : String; Deadline : Counter) is
      Effect, Local, Vendor : C.File_Effect;
      Observed : O.Observation; Snapshot : S.Snapshot; Payload : P.Inventory;
      Item : P.Payload_Entry; Media : MC_FS.Root; File : MC_FS.File;
      Prefix, Archive, Original, Again : Digest; Size, Again_Size : Counter; Status : Outcome;
      Data : Bytes (1 .. 65_536) := (others => 0); Content : Bytes (1 .. 1_024); Used, N : Natural;
      FD : MC_Posix.FD := -1; Ignored : Interfaces.C.int;
      procedure Need (Label_Text : String) is
      begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
      procedure Deny (Label_Text : String; Expected : Outcome) is
      begin
         Prefix := (others => 1); Size := 1;
         Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Prefix, Size, Status);
         Expect (Status = Expected and then Prefix = Zero_Digest and then Size = 0, Label_Text & Outcome'Image (Status));
      end Deny;
      procedure Emit (Label_Text : String) is
         Frames : Pkg_Tar_Framing.Index; Total : Natural;
      begin
         Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Prefix, Size, Status); Need ("prepare " & Label_Text);
         Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Again, Again_Size, Status); Need ("repeat " & Label_Text);
         Expect (Again = Prefix and then Again_Size = Size, "deterministic retained attributes");
         Data := (others => 0);
         MC_Store.Read_Object (Store, Prefix, Data, Used, Status); Need ("read prefix");
         MC_Store.Read_Object (Store, Effect.Content, Content, N, Status); Need ("read exact content");
         Expect (Counter (N) = Size and then Used mod 512 = 0, "exact prefix and content size");
         Data (Used + 1 .. Used + N) := Content (1 .. N); Total := Used + ((N + 511) / 512) * 512 + 1_024;
         MC_Store.Put (Store, Data (1 .. Total), Archive, Status); Need ("retain independent single-entry archive");
         MC_Store.Open_Object (Store, Archive, File, Status); Need ("open complete archive");
         Pkg_Tar_Framing.Scan (File, Counter (Total), Deadline, Frames, Status); MC_FS.Close (File); Need ("scan complete archive");
         Expect (Pkg_Tar_Framing.Count (Frames) = 1, "exactly one complete regular entry");
         Ada.Text_IO.Put_Line ("ENTRY " & Label_Text & " " & MC_Hex.Encode (Archive) & " " & MC_Hex.Encode (Effect.Object)
            & " " & MC_Hex.Encode (Effect.Permission_Override) & " " & MC_Hex.Encode (Prefix) & " " & MC_Hex.Encode (Effect.Content));
      end Emit;
   begin
      O.Load (Store, Observation, Path, Deadline, Observed, Status); Need ("adapter source observation");
      declare Attr : constant O.File_Attributes := O.Attributes (Observed); begin
         Local := (P.Byte_Strings.To_Bounded_String (Path), P.Byte_Strings.To_Bounded_String (Path),
            O.Image (Observed).Content, C.Local_Observation, Observation, Zero_Digest,
            Attr.Node.Mode and 8#7777#, Attr.Node.UID, Attr.Node.GID);
      end;
      Effect := Local; Emit ("local");
      Effect.Path := P.Byte_Strings.To_Bounded_String ("/backup-" & Character'Val (255)); Emit ("backup");
      Effect := Local; Effect.Mode := Effect.Mode xor 1; Deny ("numeric mode assertion required", Conflict);
      Effect := Local; Effect.UID := Effect.UID xor 1; Deny ("numeric owner assertion required", Conflict);
      Effect := Local; Effect.Content := Observation; Deny ("content identity assertion required", Conflict);
      Effect := Local; Effect.Source_Path := P.Byte_Strings.To_Bounded_String ("/wrong"); Deny ("observation source path required", Conflict);
      Effect := Local; Effect.Permission_Override := Observation; Deny ("local override forbidden", Invalid_Input);
      Effect := Local; Effect.Path := P.Byte_Strings.To_Bounded_String ("/../bad"); Deny ("destination traversal refused", Invalid_Input);
      Effect := Local;
      Pkg_Configuration_Entry.Prepare (Store, Effect, 0, Prefix, Size, Status);
      Expect (Status = Stale and then Prefix = Zero_Digest and then Size = 0, "expired adapter deadline");
      MC_FS.Open_Root (Ada.Directories.Full_Name (Media_Path), Media, Status); Need ("adapter original media");
      MC_FS.Open_Read (Media, "base.deb", File, Status); Need ("vendor original file");
      MC_Store.Import_File (Store, File, 1_048_576, Original, Status); MC_FS.Close (File); Need ("retained vendor original");
      P.Stage (Store, Original, Deadline, Payload, Status); Need ("vendor attributes");
      P.Read_Entry (Payload, P.Find (Payload, "dir/file"), Item, Status); Need ("vendor regular entry");
      Vendor := (P.Byte_Strings.To_Bounded_String ("/vendor"), P.Byte_Strings.To_Bounded_String ("/dir/file"),
         Item.Values.Content, C.Vendor_Payload, Original, Zero_Digest,
         Item.Values.Mode and 8#7777#, Item.Values.UID, Item.Values.GID);
      Effect := Vendor; Emit ("vendor");
      declare Dir : aliased constant String := "dir" & ASCII.NUL;
         Name : aliased constant String := "dir/file" & ASCII.NUL;
         Edited : aliased constant String := "edited";
      begin
         Expect (MC_Posix.Mkdirat (MC_Posix.FD (Root_FD), Dir'Address, 8#700#) = 0, "private override parent");
         FD := MC_Posix.Openat (MC_Posix.FD (Root_FD), Name'Address,
            MC_Posix.O_WRONLY + MC_Posix.O_CREAT + MC_Posix.O_EXCL + MC_Posix.O_CLOEXEC, 8#600#);
         Expect (FD >= 0 and then MC_Posix.Write (FD, Edited'Address, Edited'Length) = Edited'Length, "private local override");
         Ignored := MC_Posix.Close (FD); FD := -1;
      end;
      S.Capture (Store, Root_FD, "/dir/file", 1024, Deadline, Snapshot, Status); Need ("actual vendor permission override");
      Effect.Permission_Override := S.Metadata (Snapshot); S.Clear (Snapshot);
      O.Load (Store, Effect.Permission_Override, "/dir/file", Deadline, Observed, Status); Need ("read override");
      Effect.Mode := 8#600#; Effect.UID := O.Attributes (Observed).Node.UID; Effect.GID := O.Attributes (Observed).Node.GID;
      Effect.Path := P.Byte_Strings.To_Bounded_String ("/renamed-vendor"); Emit ("override");
      Effect.Mode := 8#640#; Deny ("override assertions required", Conflict);
      Effect := Vendor; Effect.Permission_Override := Observation; Deny ("override bound to original path", Conflict);
      Effect := Vendor; Effect.Source_Path := P.Byte_Strings.To_Bounded_String ("/dir"); Deny ("directory not a configuration file", Unsupported);
      MC_FS.Close (Media); O.Clear (Observed); P.Clear (Payload);
   exception when others =>
      Ignored := MC_Posix.Close (FD); MC_FS.Close (File); MC_FS.Close (Media);
      S.Clear (Snapshot); O.Clear (Observed); P.Clear (Payload); raise;
   end Run;
end Configuration_Entry_Test;
