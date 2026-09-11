-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Clock; with MC_Posix; with MC_Store; with MC_FS; with MC_Codec; with MC_SHA256; with MC_Hex;
with Pkg_Conffile_Choice; with Pkg_Conffile_Transition; with Pkg_Deb_Payload;
with Test_Support; use Test_Support;
procedure Run_Conffile_Choice_Tests with SPARK_Mode => Off is
   package C renames Pkg_Conffile_Choice; package T renames Pkg_Conffile_Transition;
   use type Interfaces.C.int; use type Interfaces.C.long; use type T.Action; use type Byte; use type Wide;
   use type C.Attribute_Source; use type C.File_Effect; use type Word;
   package Names renames Pkg_Deb_Payload.Byte_Strings;
   Target_Effect, Backup_Effect : C.File_Effect;
   Empty_Effect : constant C.File_Effect := (others => <>);
   Store : MC_Store.Store; Media : MC_FS.Root; File : MC_FS.File; Value : C.Proposal;
   Root : MC_Posix.FD := -1; Ignored : Interfaces.C.int; Status : Outcome; Deadline : Counter;
   Old, New_Source, Omitted, Removal, Ordinary, Expected, Decision, Closure : Digest;
   Wire : Bytes (1 .. 4096); Used : Natural;
   Path : constant String := "/etc/fixture.conf"; Backup : constant String := "/etc/fixture.conf.save";
   Context : Digest := (others => 3);
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Hash (Text : String) return Digest is
      B : Bytes (1 .. Text'Length);
   begin for I in B'Range loop B (I) := Character'Pos (Text (Text'First + I - 1)); end loop; return MC_SHA256.Hash (B); end Hash;
   procedure Load (Name : String; Result : out Digest) is
   begin
      MC_FS.Open_Read (Media, Name & ".deb", File, Status); Need ("open original");
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Result, Status); MC_FS.Close (File); Need ("retain original");
   end Load;
   procedure Write (Name, Text : String) is
      N : aliased constant String := Name & ASCII.NUL; Content : aliased constant String := Text; FD : MC_Posix.FD;
   begin
      FD := MC_Posix.Openat (Root, N'Address, MC_Posix.O_RDWR + MC_Posix.O_CREAT + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 8#600#);
      Expect (FD >= 0, "open private fixture"); Expect (MC_Posix.Ftruncate (FD, 0) = 0, "truncate fixture");
      Expect (MC_Posix.Write (FD, Content'Address, Content'Length) = Content'Length, "write fixture"); Ignored := MC_Posix.Close (FD);
   end Write;
   procedure Drop (Name : String) is
      N : aliased constant String := Name & ASCII.NUL;
   begin Expect (MC_Posix.Unlinkat (Root, N'Address, 0) = 0, "remove fixture"); end Drop;
   procedure Prepare (Mode : C.Operation := C.Update; Incoming : Digest := New_Source; Prior : Digest := Old) is
   begin
      C.Prepare (Store, Integer (Root), (others => 1), (others => 2), Context, Mode, Path,
         Prior, Incoming, 1024, Deadline, Value, Status); Need ("prepare original-bound choice");
      Expected := C.Address (Value); Expect (Expected /= Zero_Digest, "retained proposal");
   end Prepare;
   procedure Resolve (Selection : T.Choice; Destination : String) is
   begin C.Resolve (Store, Value, Expected, Selection, Destination, Deadline, Decision, Closure, Status); end Resolve;
   procedure Cleared is
   begin Expect (Decision = Zero_Digest and then Closure = Zero_Digest and then C.Address (Value) = Zero_Digest, "failure clears session and outputs"); end Cleared;
   procedure Read_Choice is
      Fresh : C.Proposal; Current_Decision, Current_Closure : Digest;
   begin
      MC_Store.Read_Object (Store, Decision, Wire, Used, Status); Need ("read choice record");
      Expect (Used >= 368 and then Wire (1 .. 8) = Bytes'(78,73,65,67,67,72,48,50) and then Wire (9 .. 40) = Expected, "exact proposal binding");
      C.Reobserve (Store, Integer (Root), (others => 1), (others => 2), Context,
         Expected, Decision, Closure, 1024, Deadline + 1, Fresh, Current_Decision, Current_Closure, Status);
      Need ("fresh observation of complete saved choice");
      Expect (C.Address (Fresh) /= Expected and then Current_Decision /= Decision and then Current_Closure /= Closure,
         "new observation lifetime has distinct records without rewriting history");
      C.Recheck (Store, Fresh, Current_Decision, Current_Closure, Deadline + 1, Status); Need ("fresh choice live recheck");
      C.Clear (Fresh);
   end Read_Choice;
   procedure Effects is
      procedure Encoded (At_Byte : Positive; Item : C.File_Effect) is
      begin
         Expect (Wire (At_Byte) = C.Attribute_Source'Pos (Item.Source)
            and then Wire (At_Byte + 1 .. At_Byte + 3) = Bytes'(0, 0, 0)
            and then MC_Codec.U32 (Wire, At_Byte + 4) = Item.Mode
            and then MC_Codec.U32 (Wire, At_Byte + 8) = Item.UID
            and then MC_Codec.U32 (Wire, At_Byte + 12) = Item.GID
            and then Wire (At_Byte + 16 .. At_Byte + 47) = Item.Object
            and then Wire (At_Byte + 48 .. At_Byte + 79) = Item.Permission_Override, "exact persisted attribute source");
      end Encoded;
   begin
      C.Read_Effects (Store, Value, Decision, Closure, Deadline, Target_Effect, Backup_Effect, Status); Need ("read rechecked effects");
      Expect (Names.To_String (Target_Effect.Path) = Path, "target destination retained");
      Encoded (209, Target_Effect); Encoded (289, Backup_Effect);
      Expect (Used = 368 + Names.Length (Backup_Effect.Path)
         and then Natural (MC_Codec.U32 (Wire, 205)) = Names.Length (Backup_Effect.Path), "version two exact path framing");
      for I in 1 .. Names.Length (Backup_Effect.Path) loop
         Expect (Wire (368 + I) = Character'Pos (Names.Element (Backup_Effect.Path, I)), "backup destination bytes");
      end loop;
   end Effects;
   procedure Local_Permissions (Item : C.File_Effect; Mode : Word := 8#600#) is
   begin
      Expect (Item.Mode = Mode and then Item.UID = Word (MC_Posix.Euid) and then Item.GID = Word (MC_Posix.Egid), "actual local numeric permissions");
   end Local_Permissions;
   procedure Chmod (Mode : Interfaces.C.unsigned) is
      N : aliased constant String := "etc/fixture.conf" & ASCII.NUL; FD : MC_Posix.FD;
   begin
      FD := MC_Posix.Openat (Root, N'Address, MC_Posix.O_RDONLY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
      Expect (FD >= 0, "open private permissions fixture"); Expect (MC_Posix.Fchmod (FD, Mode) = 0, "set private permissions");
      Ignored := MC_Posix.Close (FD);
   end Chmod;
begin
   Expect (Ada.Command_Line.Argument_Count = 3, "store root and media");
   MC_Runtime.Initialize (Status); Need ("runtime"); MC_Clock.Boottime_Milliseconds (Deadline, Status); Need ("clock"); Deadline := Deadline + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("CAS");
   MC_FS.Open_Root (Ada.Command_Line.Argument (3), Media, Status); Need ("media");
   declare N : aliased constant String := Ada.Command_Line.Argument (2) & ASCII.NUL; E : aliased constant String := "etc" & ASCII.NUL; begin
      Root := MC_Posix.Open (N'Address, MC_Posix.O_PATH + MC_Posix.O_DIRECTORY + MC_Posix.O_NOFOLLOW + MC_Posix.O_CLOEXEC, 0);
      Expect (Root >= 0, "root descriptor"); Expect (MC_Posix.Mkdirat (Root, E'Address, 8#700#) = 0, "private etc");
   end;
   Load ("normal", Old); Load ("updated", New_Source); Load ("omitted", Omitted); Load ("remove-current", Removal); Load ("absent", Ordinary);
   Write ("etc/fixture.conf", "local"); Prepare;
   MC_Store.Read_Object (Store, Expected, Wire, Used, Status); Need ("read proposal");
   Expect (Used = 344 + Path'Length and then MC_Codec.U64 (Wire, 333) = Wide (Deadline), "initial deadline bound into proposal");
   Expect (C.Pending (Value).Effect = T.Require_Choice, "both changes require choice");
   C.Resolve (Store, Value, Zero_Digest, T.Keep_Local, Backup, Deadline, Decision, Closure, Status);
   Expect (Status = Invalid_Input, "different proposal refused"); Cleared;
   Prepare; Write ("etc/fixture.conf", "edit"); Resolve (T.Keep_Local, Backup);
   Expect (Status = Stale, "edit while awaiting choice refused"); Cleared;
   Write ("etc/fixture.conf", "local"); Prepare; Resolve (T.Unresolved, "");
   Expect (Status = Conflict, "unresolved cannot commit"); Cleared;
   Prepare; Resolve (T.Use_Vendor, ""); Expect (Status = Invalid_Input, "required backup cannot disappear"); Cleared;
   Prepare; Resolve (T.Use_Vendor, Path & "/child"); Expect (Status = Invalid_Input, "backup cannot overlap target namespace"); Cleared;
   Write ("etc/fixture.conf.save", "existing"); Prepare; Resolve (T.Keep_Local, Backup);
   Expect (Status = Conflict, "occupied backup never overwritten"); Cleared; Drop ("etc/fixture.conf.save");
   Prepare; Resolve (T.Keep_Local, Backup); Need ("keep local"); Read_Choice;
   Expect (Wire (45 .. 76) = Hash ("local") and then Wire (77 .. 108) = Hash ("second" & ASCII.LF), "retain local and back up vendor");
   Expect (Wire (141 .. 172) = New_Source, "baseline advances to incoming original even when local kept");
   Effects; Local_Permissions (Target_Effect); Local_Permissions (Backup_Effect);
   Expect (Target_Effect.Source = C.Local_Observation and then Target_Effect.Object /= Zero_Digest
      and then Target_Effect.Permission_Override = Zero_Digest, "kept local retains full observation");
   Expect (Backup_Effect.Source = C.Vendor_Payload and then Backup_Effect.Object = New_Source
      and then Backup_Effect.Permission_Override = Target_Effect.Object, "vendor backup inherits local permissions only");
   Expect (Names.To_String (Backup_Effect.Path) = Backup and then Names.To_String (Backup_Effect.Source_Path) = Path
      and then Names.To_String (Target_Effect.Source_Path) = Path, "renamed backup keeps original attribute source path");
   C.Recheck (Store, Value, Decision, Closure, Deadline, Status); Need ("live decision and exact references");
   MC_Store.Read_Object (Store, Closure, Wire, Used, Status); Need ("closure");
   declare Count : constant Natural := Natural (MC_Codec.U32 (Wire, 73)); Previous : Digest := Zero_Digest;
      Have_Old, Have_New, Have_Local, Have_Choice : Boolean := False; H : Digest;
   begin
      Expect (Used = 76 + 32 * Count and then Count in 5 .. 32 and then Wire (9 .. 40) = Expected and then Wire (41 .. 72) = Decision, "exact closure framing");
      for I in 0 .. Count - 1 loop
         H := Wire (77 + 32 * I .. 108 + 32 * I); Expect (H > Previous, "unique sorted retained references"); Previous := H;
         Have_Old := Have_Old or H = Old; Have_New := Have_New or H = New_Source;
         Have_Local := Have_Local or H = Hash ("local"); Have_Choice := Have_Choice or H = Decision;
      end loop;
      Expect (Have_Old and Have_New and Have_Local and Have_Choice, "both originals local and choice retained");
   end;
   Write ("etc/fixture.conf.save", "late"); C.Read_Effects (Store, Value, Decision, Closure, Deadline, Target_Effect, Backup_Effect, Status);
   Expect (Target_Effect = Empty_Effect and then Backup_Effect = Empty_Effect, "stale effects cleared");
   Expect (Status = Stale and then C.Address (Value) = Zero_Digest, "late backup creation invalidates choice"); Drop ("etc/fixture.conf.save");
   Prepare; Resolve (T.Use_Vendor, Backup); Need ("use vendor"); Read_Choice;
   Expect (Wire (45 .. 76) = Hash ("second" & ASCII.LF) and then Wire (77 .. 108) = Hash ("local"), "retain replaced local content");
   Effects; Local_Permissions (Target_Effect); Local_Permissions (Backup_Effect);
   Expect (Target_Effect.Source = C.Vendor_Payload and then Target_Effect.Object = New_Source
      and then Target_Effect.Permission_Override = Backup_Effect.Object, "replacement inherits local permissions");
   Expect (Backup_Effect.Source = C.Local_Observation and then Backup_Effect.Object /= Zero_Digest
      and then Backup_Effect.Permission_Override = Zero_Digest, "local backup retains full observation");
   Resolve (T.Keep_Local, Backup); Expect (Status = Invalid_Input, "selection cannot be rebound"); Cleared;
   Chmod (8#6740#); Prepare; Resolve (T.Use_Vendor, Backup); Need ("special permissions choice"); Read_Choice; Effects;
   Local_Permissions (Target_Effect, 8#6740#); Local_Permissions (Backup_Effect, 8#6740#);
   Chmod (8#600#); C.Read_Effects (Store, Value, Decision, Closure, Deadline, Target_Effect, Backup_Effect, Status);
   Expect (Status = Stale and then Target_Effect = Empty_Effect and then Backup_Effect = Empty_Effect, "permission change refuses stale numeric effects");
   Prepare (C.Remove, Zero_Digest); Resolve (T.Unresolved, ""); Need ("ordinary removal"); Read_Choice;
   Expect (Wire (45 .. 76) = Hash ("local") and then Wire (141 .. 172) = Old, "remove retains configuration and baseline");
   Prepare (C.Purge, Zero_Digest); Resolve (T.Unresolved, ""); Need ("purge"); Read_Choice;
   Expect (Wire (45 .. 76) = Zero_Digest and then Wire (141 .. 172) = Zero_Digest, "purge clears active baseline");
   Effects;
   Expect (Target_Effect.Source = C.No_File and then Target_Effect.Object = Zero_Digest
      and then Target_Effect.Permission_Override = Zero_Digest and then Target_Effect.Mode = 0
      and then Target_Effect.UID = 0 and then Target_Effect.GID = 0
      and then Names.Length (Target_Effect.Source_Path) = 0 and then Backup_Effect = Empty_Effect, "purge absence has no invented attributes");
   Prepare (Incoming => Removal); Resolve (T.Unresolved, Backup); Need ("declared removal"); Read_Choice;
   Expect (Wire (42) = T.Action'Pos (T.Backup_And_Delete) and then Wire (77 .. 108) = Hash ("local") and then Wire (141 .. 172) = Old, "remove flag preserves modified local and prior baseline");
   Prepare (Incoming => Omitted); Resolve (T.Unresolved, ""); Need ("omitted local retained"); Read_Choice;
   Expect (Wire (45 .. 76) = Hash ("local") and then Wire (141 .. 172) = Old, "omission not purge");
   Drop ("etc/fixture.conf"); Prepare (Incoming => Omitted); Resolve (T.Unresolved, ""); Need ("omitted and absent"); Read_Choice;
   Expect (Wire (141 .. 172) = Zero_Digest, "absent obsolete baseline cleared");
   Prepare (Prior => Zero_Digest); Resolve (T.Unresolved, ""); Need ("first install"); Read_Choice;
   Expect (Wire (45 .. 76) = Hash ("second" & ASCII.LF), "first install content");
   Effects;
   Expect (Target_Effect.Source = C.Vendor_Payload and then Target_Effect.Object = New_Source
      and then Target_Effect.Permission_Override = Zero_Digest and then Target_Effect.Mode = 8#640#
      and then Target_Effect.UID = 1001 and then Target_Effect.GID = 1002 and then Backup_Effect = Empty_Effect, "first install uses archive permissions without local override");
   Prepare (Prior => Zero_Digest); Resolve (T.Keep_Local, ""); Expect (Status = Invalid_Input, "unused selection not silently ignored"); Cleared;
   C.Prepare (Store, Integer (Root), (others => 1), (others => 2), Context, C.Update, Path, Old, Ordinary, 1024, Deadline, Value, Status);
   Expect (Status = Unsupported and then C.Address (Value) = Zero_Digest, "ordinary-file conversion needs separate effects");
   Prepare; declare A : constant Digest := Expected; begin Context := (others => 4); Prepare; Expect (Expected /= A, "enclosing intent changes proposal"); end;
   C.Resolve (Store, Value, Expected, T.Unresolved, "", 0, Decision, Closure, Status); Expect (Status = Stale, "expired decision refused"); Cleared;
   Prepare (Prior => Zero_Digest); Resolve (T.Unresolved, ""); Need ("prepare closure mismatch check");
   C.Read_Effects (Store, Value, Decision, (others => 6), Deadline, Target_Effect, Backup_Effect, Status);
   Expect (Target_Effect = Empty_Effect and then Backup_Effect = Empty_Effect, "unrelated closure clears effects");
   Expect (Status = Invalid_Input and then C.Address (Value) = Zero_Digest, "unrelated closure refused");
   Prepare (Prior => Zero_Digest); Resolve (T.Unresolved, ""); Need ("prepare missing retained object check");
   declare Private_CAS : MC_FS.Root; Hex : constant String := MC_Hex.Encode (New_Source); begin
      MC_FS.Open_Root (Ada.Command_Line.Argument (1), Private_CAS, Status); Need ("private CAS fault fixture");
      MC_FS.Remove (Private_CAS, "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64), False, Status);
      MC_FS.Close (Private_CAS); Need ("remove isolated retained original");
   end;
   C.Recheck (Store, Value, Decision, Closure, Deadline, Status);
   Expect (Status /= OK and then C.Address (Value) = Zero_Digest, "missing retained source invalidates candidate");
   MC_Store.Open_Object (Store, New_Source, File, Status); MC_FS.Close (File);
   Expect (Status /= OK, "recheck does not recreate missing original");
   MC_Store.Read_Object (Store, Hash ("local"), Wire, Used, Status); Need ("old local still retained"); Expect (Used = 5, "old bytes survive all candidate operations");
   C.Clear (Value); Ignored := MC_Posix.Close (Root); Root := -1; MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => C.Clear (Value); Ignored := MC_Posix.Close (Root); MC_FS.Close (File); MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Conffile_Choice_Tests;
