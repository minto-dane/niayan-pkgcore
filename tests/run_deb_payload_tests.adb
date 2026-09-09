-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Interfaces; with Interfaces.C; with System;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_SHA256; with MC_Store;
with Pkg_Deb_Payload;
with Test_Support; use Test_Support;
procedure Run_Deb_Payload_Tests with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Interfaces.Integer_64; use type Word;
   use type System.Address; use type Wide;
   function Use_Locale (Locale : System.Address) return System.Address
      with Import, Convention => C, External_Name => "uselocale";
   function Set_Locale (Category : Interfaces.C.int; Name : Interfaces.C.char_array) return System.Address
      with Import, Convention => C, External_Name => "setlocale";
   package P renames Pkg_Deb_Payload; use type P.Entry_Kind;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome;
   Result : P.Inventory; Original : Digest; Now, Deadline : Counter; Item : P.Payload_Entry;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Hex (Text : String) return String is
      B : Bytes (1 .. Text'Length);
   begin
      for I in B'Range loop B (I) := Character'Pos (Text (Text'First + I - 1)); end loop;
      return MC_Hex.Encode (B);
   end Hex;
   procedure Object (Hash : Digest; Size : Counter := Counter'Last) is
      F : MC_FS.File; D : Digest; N : Counter;
   begin
      MC_Store.Open_Object (Store, Hash, F, Status); Need ("CAS object");
      MC_FS.Hash (F, MC_Store.Max_Object_Size, D, N, Status); Need ("CAS hash"); MC_FS.Close (F);
      Expect (D = Hash and then (Size = Counter'Last or else Size = N), "complete CAS content");
   end Object;
   procedure Import (Name : String) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, F, Status); Need ("fixture open " & Name);
      MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Original, Status); Need ("fixture import"); MC_FS.Close (F);
   end Import;
   procedure Run (Name : String) is
      Caller_Locale : constant System.Address := Use_Locale (System.Null_Address);
   begin
      Import (Name); P.Stage (Store, Original, Deadline, Result, Status); Need ("payload " & Name);
      Expect (Use_Locale (System.Null_Address) = Caller_Locale, "caller locale restored after success");
      Expect (P.Original_Hash (Result) = Original and then P.Tar_Hash (Result) /= Zero_Digest, "bound original inventory");
      Object (P.Tar_Hash (Result));
      for I in 1 .. P.Count (Result) loop
         P.Read_Entry (Result, I, Item, Status); Need ("inventory read");
         Expect (P.Find (Result, P.Byte_Strings.To_String (Item.Path)) = I, "canonical index roundtrip");
         Object (Item.Values.Xattrs); Object (Item.Values.ACLs);
         if Item.Values.Kind in P.Regular | P.Symbolic_Link | P.Hard_Link then Object (Item.Values.Content, Item.Values.Content_Size); end if;
      end loop;
   end Run;
   procedure Rejected (Name : String) is
      Caller_Locale : constant System.Address := Use_Locale (System.Null_Address);
   begin
      Import (Name & ".deb"); P.Stage (Store, Original, Deadline, Result, Status);
      Expect (Use_Locale (System.Null_Address) = Caller_Locale, "caller locale restored after failure");
      Expect (Status in Corrupt | Unsupported | Exhausted, "rejected " & Name & Outcome'Image (Status));
      Expect (P.Count (Result) = 0 and then P.Original_Hash (Result) = Zero_Digest
         and then P.Tar_Hash (Result) = Zero_Digest, "failure publishes no inventory");
   end Rejected;
   procedure Clock (Name : String; Value : P.Timestamp) is
   begin
      Ada.Text_IO.Put_Line (Name & " " & Boolean'Image (Value.Present) & " " & Interfaces.Integer_64'Image (Value.Seconds) & Natural'Image (Value.Nanoseconds));
   end Clock;
   procedure Dump is
   begin
      Ada.Text_IO.Put_Line ("ORIGINAL " & MC_Hex.Encode (P.Original_Hash (Result)));
      Ada.Text_IO.Put_Line ("TAR " & MC_Hex.Encode (P.Tar_Hash (Result)));
      Ada.Text_IO.Put_Line ("COUNT" & Natural'Image (P.Count (Result)));
      for I in 1 .. P.Count (Result) loop
         P.Read_Entry (Result, I, Item, Status); Need ("dump read");
         Ada.Text_IO.Put_Line ("ENTRY" & Natural'Image (I));
         Ada.Text_IO.Put_Line ("PATH " & Hex (P.Byte_Strings.To_String (Item.Path)));
         Ada.Text_IO.Put_Line ("LINK " & Hex (P.Byte_Strings.To_String (Item.Link_Target)));
         Ada.Text_IO.Put_Line ("UNAME " & Hex (P.Byte_Strings.To_String (Item.User_Name)));
         Ada.Text_IO.Put_Line ("GNAME " & Hex (P.Byte_Strings.To_String (Item.Group_Name)));
         Ada.Text_IO.Put_Line ("ATTR " & P.Entry_Kind'Image (Item.Values.Kind) & Word'Image (Item.Values.Mode)
            & Word'Image (Item.Values.UID) & Word'Image (Item.Values.GID) & Word'Image (Item.Values.Device_Major) & Word'Image (Item.Values.Device_Minor)
            & Counter'Image (Item.Values.Archive_Size) & Counter'Image (Item.Values.Content_Size) & Natural'Image (Item.Values.Inode_Entry)
            & Wide'Image (Item.Values.Flags_Set) & Wide'Image (Item.Values.Flags_Clear));
         Ada.Text_IO.Put_Line ("CONTENT " & MC_Hex.Encode (Item.Values.Content));
         Ada.Text_IO.Put_Line ("XATTR " & MC_Hex.Encode (Item.Values.Xattrs));
         Ada.Text_IO.Put_Line ("ACL " & MC_Hex.Encode (Item.Values.ACLs));
         Clock ("MTIME", Item.Values.Modified); Clock ("ATIME", Item.Values.Accessed);
         Clock ("CTIME", Item.Values.Changed); Clock ("BTIME", Item.Values.Created);
      end loop;
   end Dump;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 3, "fresh CAS, fixtures and optional original filename");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      P.Stage (Store, Zero_Digest, 0, Result, Status);
      Expect (Status = Denied and then P.Count (Result) = 0, "root payload refused before access"); Report; return;
   end if;
   Expect (Set_Locale (0, Interfaces.C.To_C ("")) /= System.Null_Address, "test caller display locale");
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture root");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 300_000;
   if Ada.Command_Line.Argument_Count = 3 then
      Run (Ada.Command_Line.Argument (3)); Dump;
   else
      Run ("basic.deb"); Expect (P.Count (Result) = 13, "all basic kinds retained");
      P.Read_Entry (Result, 3, Item, Status); Need ("regular attributes");
      Expect (Item.Values.Kind = P.Regular and then Item.Values.Mode = 8#6751#
         and then Item.Values.UID = 123 and then Item.Values.GID = 456
         and then Item.Values.Content_Size = 10, "permission and ownership bits retained");
      P.Read_Entry (Result, 5, Item, Status); Need ("forward hardlink");
      Expect (Item.Values.Kind = P.Hard_Link and then Item.Values.Inode_Entry = 3
         and then Item.Values.Content_Size = 10, "forward chain reaches regular inode");
      P.Read_Entry (Result, 10, Item, Status); Need ("device");
      Expect (Item.Values.Kind = P.Character_Device and then Item.Values.Device_Major = 1
         and then Item.Values.Device_Minor = 3, "device identity retained without creation");
      Run ("empty.deb"); Expect (P.Count (Result) = 0, "empty archive inventory");
      Run ("gnu.deb"); Run ("pax.deb"); Run ("unicode.deb"); Rejected ("global");
      Run ("multilingual.deb"); Run ("gnu-numeric.deb"); Run ("flags.deb");
      P.Read_Entry (Result, 1, Item, Status); Need ("inode flags");
      Expect (Item.Values.Flags_Set /= 0 and then Item.Values.Flags_Clear = 0, "known flags retained");
      Run ("attributes.deb"); P.Read_Entry (Result, 1, Item, Status); Need ("extended attributes");
      Expect (Item.Values.UID = Word'Last and then Item.Values.GID = Word'Last - 1
         and then Item.Values.Modified.Seconds = 1_700_000_000 and then Item.Values.Modified.Nanoseconds = 123_456_789
         and then Item.Values.Accessed.Nanoseconds = 7 and then Item.Values.Changed.Nanoseconds = 420_000_000
         and then Item.Values.Created.Nanoseconds = 750_000_000, "full numeric ids and four nanosecond clocks");
      Run ("negative-clock.deb"); P.Read_Entry (Result, 1, Item, Status); Need ("negative timestamp");
      Expect (Item.Values.Modified.Seconds = -2 and then Item.Values.Modified.Nanoseconds = 750_000_000, "normalized negative fractional time");
      Run ("negative-zero.deb"); P.Read_Entry (Result, 1, Item, Status); Need ("negative subsecond timestamp");
      Expect (Item.Values.Modified.Seconds = -1 and then Item.Values.Modified.Nanoseconds = 999_999_999
         and then Item.Values.Accessed.Nanoseconds = 123_456_789, "negative zero and exact trailing precision");
      Rejected ("duplicate"); Rejected ("ancestor"); Rejected ("parent"); Rejected ("absolute-path");
      Rejected ("dot-component"); Rejected ("empty-component"); Rejected ("escape-link"); Rejected ("missing-hardlink");
      Rejected ("cycle"); Rejected ("hardlink-directory"); Rejected ("unknown-pax"); Rejected ("sparse-pax");
      Rejected ("clock-precision"); Rejected ("uid-overflow"); Rejected ("checksum"); Rejected ("padding");
      Rejected ("trailing"); Rejected ("one-terminator"); Rejected ("no-terminator"); Rejected ("truncated"); Rejected ("orphan-local");
      Rejected ("unknown-flags"); Rejected ("invalid-acl"); Rejected ("too-many-xattrs"); Rejected ("repeated-local");
      Rejected ("numeric-tail");
      Rejected ("empty-pax-name"); Rejected ("duplicate-pax");
      Run ("basic.deb"); P.Stage (Store, Original, 0, Result, Status);
      Expect (Status = Stale and then P.Count (Result) = 0, "expired request clears previous inventory");
      Run ("basic.deb"); P.Clear (Result); P.Clear (Result);
      Expect (P.Count (Result) = 0 and then P.Find (Result, "usr/a") = 0, "idempotent clear");
      P.Read_Entry (Result, 1, Item, Status); Expect (Status = Invalid_Input, "empty inventory bounds");
   end if;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Payload_Tests;
