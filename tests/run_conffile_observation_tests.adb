-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Interfaces; with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Clock; with MC_Store; with MC_Posix; with MC_FS; with MC_Hex;
with Pkg_Conffile_Snapshot; with Pkg_Conffile_Observation; with Pkg_Conffile_Transition; with Pkg_Deb_Payload;
with Configuration_Entry_Test; with Pkg_Configuration_Entry; with Pkg_Conffile_Choice;
with Test_Support; use Test_Support;
procedure Run_Conffile_Observation_Tests with SPARK_Mode => Off is
   package O renames Pkg_Conffile_Observation; package S renames Pkg_Conffile_Snapshot;
   package T renames Pkg_Conffile_Transition; package P renames Pkg_Deb_Payload;
   use type Interfaces.C.int; use type Interfaces.C.long; use type Interfaces.Integer_64;
   use type T.File_Kind; use type Wide; use type Word; use type Byte;
   Store : MC_Store.Store; Snapshot : S.Snapshot; Observed : O.Observation;
   Root, FD : MC_Posix.FD := -1; Ignored : Interfaces.C.int;
   Status : Outcome; Deadline : Counter; Original, Changed, Saved_Content : Digest;
   Wire, Altered : Bytes (1 .. 4096); Used, Read : Natural;
   Value : Bytes (1 .. 64); Name : P.Byte_Strings.Bounded_String; Parent : O.Node_Identity;
   File_Name : aliased constant String := "raw-" & Character'Val (255) & ASCII.NUL;
   Path : constant String := "/" & File_Name (1 .. File_Name'Last - 1);
   Content : aliased constant String := "content";
   Xname : aliased constant String := "user.observed" & ASCII.NUL;
   Empty_Name : aliased constant String := "user.empty" & ASCII.NUL;
   ACL_Name : aliased constant String := "system.posix_acl_access" & ASCII.NUL;
   Raw : aliased constant Bytes := (0, 255, 42);
   ACL : aliased Bytes (1 .. 44) := (others => 0);
   Times : aliased MC_Posix.Timespec_Pair := ((123, 456), (-42, 123456789));
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Put_LE (B : in out Bytes; Pos : Positive; N : Wide; Size : Positive := 8) is
      V : Wide := N;
   begin for I in 0 .. Size - 1 loop B (Pos + I) := Byte (V and 255); V := Interfaces.Shift_Right (V, 8); end loop; end Put_LE;
   procedure Reject (Label_Text : String; Length : Natural := Used) is
   begin
      MC_Store.Put (Store, Altered (1 .. Length), Changed, Status); Need ("store malformed fixture");
      O.Load (Store, Changed, Path, Deadline, Observed, Status);
      Expect (Status = Corrupt and then O.Address (Observed) = Zero_Digest and then O.Image (Observed).Kind = T.Other
              and then O.Directory_Count (Observed) = 0 and then O.Xattr_Count (Observed) = 0, Label_Text);
   end Reject;
   -- One root directory precedes the regular file in this actual observation.
   File_Start : constant Positive := 8 + 8 + Path'Length + 16 + 64 + 1;
begin
   Expect (Ada.Command_Line.Argument_Count = 3, "private CAS, root and vendor media");
   MC_Runtime.Initialize (Status); Need ("runtime"); MC_Clock.Boottime_Milliseconds (Deadline, Status); Need ("clock"); Deadline := Deadline + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("CAS");
   declare N : aliased constant String := Ada.Command_Line.Argument (2) & ASCII.NUL; begin
      Root := MC_Posix.Open (N'Address, MC_Posix.O_PATH + MC_Posix.O_DIRECTORY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
   end;
   Expect (Root >= 0, "root descriptor");
   S.Capture (Store, Integer (Root), "/missing/child", 1024, Deadline, Snapshot, Status); Need ("observe missing ancestor");
   O.Load (Store, S.Metadata (Snapshot), "/missing/child", Deadline, Observed, Status); Need ("read missing ancestor");
   Expect (O.Image (Observed).Kind = T.Missing and then O.Missing_Component (Observed) = 1 and then O.Directory_Count (Observed) = 1, "missing location retained");
   FD := MC_Posix.Openat (Root, File_Name'Address, MC_Posix.O_RDWR + MC_Posix.O_CREAT + MC_Posix.O_EXCL + MC_Posix.O_CLOEXEC, 8#640#);
   Expect (FD >= 0 and then MC_Posix.Write (FD, Content'Address, Content'Length) = Content'Length, "create local file");
   Expect (MC_Posix.Futimens (FD, Times'Address) = 0, "signed fractional times");
   Expect (MC_Posix.Fsetxattr (FD, Xname'Address, Raw'Address, Raw'Length, 0) = 0, "binary xattr");
   Expect (MC_Posix.Fsetxattr (FD, Empty_Name'Address, Raw'Address, 0, 0) = 0, "empty xattr");
   Put_LE (ACL, 1, 2, 4);
   declare Tags : constant array (1 .. 5) of Wide := (1, 2, 4, 16, 32);
      Perms : constant array (1 .. 5) of Wide := (6, 4, 0, 4, 0); Pos : Positive;
   begin
      for I in 1 .. 5 loop
         Pos := 5 + 8 * (I - 1); Put_LE (ACL, Pos, Tags (I), 2); Put_LE (ACL, Pos + 2, Perms (I), 2);
         Put_LE (ACL, Pos + 4, (if I = 2 then Wide (MC_Posix.Euid) + 1 else 16#FFFFFFFF#), 4);
      end loop;
   end;
   Expect (MC_Posix.Fsetxattr (FD, ACL_Name'Address, ACL'Address, ACL'Length, 0) = 0, "actual POSIX ACL");
   S.Capture (Store, Integer (Root), Path, 1024, Deadline, Snapshot, Status); Need ("capture all visible attributes"); Original := S.Metadata (Snapshot);
   S.Clear (Snapshot);
   O.Load (Store, Original, Path, Deadline, Observed, Status); Need ("load without live snapshot handle");
   Saved_Content := O.Image (Observed).Content;
   Expect (O.Path (Observed) = Path and then O.Image (Observed).Kind = T.Regular and then O.Missing_Component (Observed) = 0, "exact raw path and kind");
   Expect (O.Attributes (Observed).Modified.Seconds = -42 and then O.Attributes (Observed).Modified.Nanoseconds = 123456789
      and then O.Attributes (Observed).Accessed.Seconds = 123 and then O.Attributes (Observed).Accessed.Nanoseconds = 456, "signed full clocks retained");
   Expect (O.Observer_UID (Observed) = Word (MC_Posix.Euid) and then O.Observer_GID (Observed) = Word (MC_Posix.Egid)
      and then O.Attributes (Observed).Node.UID = Word (MC_Posix.Euid) and then O.Attributes (Observed).Node.Mode = 8#100640#
      and then O.Attributes (Observed).Size = 7 and then O.Attributes (Observed).Links = 1, "numeric identity mode and size");
   O.Read_Directory (Observed, 1, Parent, Status); Need ("root identity");
   Expect (Parent.Mount = O.Attributes (Observed).Node.Mount, "same observed mount");
   Expect (O.Xattr_Count (Observed) = 3, "all visible attributes present");
   O.Read_Xattr (Observed, 1, Name, Value, Read, Status); Need ("read ACL");
   Expect (P.Byte_Strings.To_String (Name) = "system.posix_acl_access" and then Read = ACL'Length and then Value (1 .. Read) = ACL, "raw ACL preserved exactly");
   O.Read_Xattr (Observed, 2, Name, Value, Read, Status); Need ("read empty attribute");
   Expect (P.Byte_Strings.To_String (Name) = "user.empty" and then Read = 0, "empty attribute not missing");
   O.Read_Xattr (Observed, 3, Name, Value, Read, Status); Need ("read binary attribute");
   Expect (Read = Raw'Length and then Value (1 .. Read) = Raw, "NUL and non-UTF8 values survive");
   O.Read_Xattr (Observed, 1, Name, Value (1 .. 1), Read, Status);
   Expect (Status = Exhausted and then Read = 0 and then P.Byte_Strings.Length (Name) = 0, "short output is not partial data");
   O.Load (Store, Original, "/other", Deadline, Observed, Status); Expect (Status = Conflict and then O.Address (Observed) = Zero_Digest, "wrong path refused");
   Configuration_Entry_Test.Run (Store, Integer (Root), Original, Path, Ada.Command_Line.Argument (3), Deadline);
   MC_Store.Read_Object (Store, Original, Wire, Used, Status); Need ("raw observation");
   Altered := Wire; Reject ("truncated header", 7);
   Altered := Wire; Reject ("truncated content address", Used - 1);
   Altered := Wire; Altered (Used + 1) := 0; Reject ("trailing data refused", Used + 1);
   Altered := Wire; Put_LE (Altered, 9, Wide'Last); Reject ("excessive path length refused");
   Altered := Wire; Put_LE (Altered, File_Start + 40, 8#10000# + 8#100640#); Reject ("invalid file type refused");
   Altered := Wire; Put_LE (Altered, File_Start + 48, 2 ** 32); Reject ("UID not truncated");
   Altered := Wire; Put_LE (Altered, File_Start + 64, 0); Reject ("zero link count refused");
   Altered := Wire; Put_LE (Altered, File_Start + 72, 8); Reject ("size must match actual content");
   Altered := Wire; Put_LE (Altered, File_Start + 80, 2 ** 63); Put_LE (Altered, File_Start + 88, 0); Reject ("attribute value outside mask refused");
   Altered := Wire; Put_LE (Altered, File_Start + 104, 1_000_000_000); Reject ("invalid fractional time refused");
   Altered := Wire; Put_LE (Altered, File_Start + 144, 2); Reject ("invalid birthtime marker refused");
   Altered := Wire; Altered (Used - 31 .. Used) := Zero_Digest; Reject ("regular zero content refused");
   declare X_Count : constant Positive := File_Start + (if Wire (File_Start + 144) = 0 then 160 else 176); begin
      Altered := Wire; Put_LE (Altered, X_Count, 32769); Reject ("attribute count bounded");
      Altered := Wire; Put_LE (Altered, X_Count + 8, 0); Reject ("empty attribute name refused");
      Altered := Wire; Altered (X_Count + 16) := 255; Reject ("unsigned byte ordering enforced");
      Altered := Wire; Put_LE (Altered, X_Count + 16 + 23, 65537); Reject ("attribute value length bounded");
      Altered := Wire; Put_LE (Altered, File_Start + 80, 2 ** 63); Put_LE (Altered, File_Start + 88, 2 ** 63);
      Put_LE (Altered, X_Count - 8, 2 ** 63); Put_LE (Altered, File_Start + 112, 2 ** 63);
      MC_Store.Put (Store, Altered (1 .. Used), Changed, Status); Need ("wide-field format fixture");
      O.Load (Store, Changed, Path, Deadline, Observed, Status); Need ("full-width fields decoded");
      Expect (O.Attributes (Observed).Attributes = 2 ** 63 and then O.Attributes (Observed).Inode_Flags = 2 ** 63
         and then O.Attributes (Observed).Modified.Seconds = Interfaces.Integer_64'First, "no flag or signed-time narrowing");
   end;
   declare Effect : Pkg_Conffile_Choice.File_Effect;
      Prefix : Digest; Size : Counter;
   begin
      Effect := (P.Byte_Strings.To_Bounded_String (Path), P.Byte_Strings.To_Bounded_String (Path), Saved_Content,
         Pkg_Conffile_Choice.Local_Observation, Changed, Zero_Digest, 8#640#, Word (MC_Posix.Euid), Word (MC_Posix.Egid));
      Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Prefix, Size, Status);
      Expect (Status = Unsupported and then Prefix = Zero_Digest and then Size = 0, "unknown active attributes not omitted");
      declare ACL_Start : Natural := 0;
         procedure Bad_ACL (Label_Text : String; Expected : Outcome) is
         begin
            MC_Store.Put (Store, Altered (1 .. Used), Effect.Object, Status); Need ("isolated ACL observation");
            Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Prefix, Size, Status);
            Expect (Status = Expected and then Prefix = Zero_Digest and then Size = 0, Label_Text & Outcome'Image (Status));
         end Bad_ACL;
      begin
         for I in 1 .. Used - ACL'Length + 1 loop
            if Wire (I .. I + ACL'Length - 1) = ACL then ACL_Start := I; exit; end if;
         end loop;
         Expect (ACL_Start /= 0, "raw ACL fixture position");
         Altered := Wire; Put_LE (Altered, ACL_Start + 16, 2 ** 31, 4);
         Bad_ACL ("ACL identity cannot saturate to a different user", Unsupported);
         Altered := Wire; Put_LE (Altered, ACL_Start + 6, 8, 2);
         Bad_ACL ("invalid ACL permissions refused", Corrupt);
         Altered := Wire; Put_LE (Altered, ACL_Start + 6, 7, 2);
         Bad_ACL ("ACL mode assertion required", Corrupt);
         Altered := Wire; Altered (ACL_Start + 12 .. ACL_Start + 19) := ACL (5 .. 12);
         Bad_ACL ("duplicate ACL owner refused", Corrupt);
      end;
      Altered := Wire; Put_LE (Altered, File_Start + 64, 2);
      MC_Store.Put (Store, Altered (1 .. Used), Effect.Object, Status); Need ("retained multiple-link observation");
      Pkg_Configuration_Entry.Prepare (Store, Effect, Deadline, Prefix, Size, Status);
      Expect (Status = Unsupported and then Prefix = Zero_Digest and then Size = 0, "unresolved local hardlink topology refused");
   end;
   O.Load (Store, Original, Path, 0, Observed, Status);
   Expect (Status = Stale and then O.Address (Observed) = Zero_Digest, "deadline refused");
   declare Private_CAS : MC_FS.Root; H : constant String := MC_Hex.Encode (Saved_Content); begin
      MC_FS.Open_Root (Ada.Command_Line.Argument (1), Private_CAS, Status); Need ("private retained-content fault");
      MC_FS.Remove (Private_CAS, "objects/" & H (1 .. 2) & "/" & H (3 .. 64), False, Status);
      MC_FS.Close (Private_CAS); Need ("remove isolated content");
   end;
   O.Load (Store, Original, Path, Deadline, Observed, Status);
   Expect (Status /= OK and then O.Address (Observed) = Zero_Digest and then O.Image (Observed).Kind = T.Other, "missing CAS content not reconstructed from live file");
   Ignored := MC_Posix.Close (FD); FD := -1; Ignored := MC_Posix.Close (Root); Root := -1;
   O.Clear (Observed); MC_Store.Close (Store); Report;
exception when others => S.Clear (Snapshot); O.Clear (Observed); Ignored := MC_Posix.Close (FD); Ignored := MC_Posix.Close (Root); MC_Store.Close (Store); raise;
end Run_Conffile_Observation_Tests;
