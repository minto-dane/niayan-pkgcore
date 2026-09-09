-- SPDX-License-Identifier: MIT
with Ada.Containers.Indefinite_Ordered_Maps; with Ada.Containers.Vectors;
with Ada.Strings.Unbounded; with Ada.Unchecked_Deallocation;
with Interfaces.C; with Interfaces.C.Strings; with System;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Deb_Container; with Pkg_Deb_Data_Stream; with Pkg_Tar_Framing;
package body Pkg_Deb_Payload with SPARK_Mode => Off is
   use Ada.Strings.Unbounded; use Interfaces.C; use Interfaces.C.Strings;
   use type System.Address; use type Interfaces.Integer_64; use type MC_FS.Entry_Info; use type Word;
   type Stored_Entry is record
      Path, Link_Target, User_Name, Group_Name : Unbounded_String;
      Values : Attributes;
   end record;
   package Entry_Vectors is new Ada.Containers.Vectors (Positive, Stored_Entry);
   package Positions is new Ada.Containers.Vectors (Positive, Positive);
   package Names is new Ada.Containers.Indefinite_Ordered_Maps (String, Positive);
   type Data is record
      Original, Tar : Digest := Zero_Digest;
      Entries : Entry_Vectors.Vector;
      By_Name : Names.Map;
      Name_Bytes : Natural := 0;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Inventory) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Inventory) is
   begin Clear (Value); end Finalize;
   function Count (Value : Inventory) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Entries.Length));
   function Original_Hash (Value : Inventory) return Digest is
     (if Value.State = null then Zero_Digest else Value.State.Original);
   function Tar_Hash (Value : Inventory) return Digest is
     (if Value.State = null then Zero_Digest else Value.State.Tar);
   function Find (Value : Inventory; Path : String) return Natural is
     (if Value.State = null or else not Value.State.By_Name.Contains (Path) then 0 else Value.State.By_Name.Element (Path));
   procedure Read_Entry (Value : Inventory; Position : Positive; Item : out Payload_Entry; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Count (Value) then return; end if;
      declare E : constant Stored_Entry := Value.State.Entries.Element (Position); begin
         Item.Path := Byte_Strings.To_Bounded_String (To_String (E.Path));
         Item.Link_Target := Byte_Strings.To_Bounded_String (To_String (E.Link_Target));
         Item.User_Name := Byte_Strings.To_Bounded_String (To_String (E.User_Name));
         Item.Group_Name := Byte_Strings.To_Bounded_String (To_String (E.Group_Name));
         Item.Values := E.Values; Status := OK;
      end;
   end Read_Entry;
   function New_Archive return System.Address with Import, Convention => C, External_Name => "archive_read_new";
   function Free_Archive (A : System.Address) return int with Import, Convention => C, External_Name => "archive_read_free";
   function Format_Tar (A : System.Address) return int with Import, Convention => C, External_Name => "archive_read_support_format_tar";
   function New_Locale (Mask : int; Name : char_array; Base : System.Address) return System.Address
      with Import, Convention => C, External_Name => "newlocale";
   function Use_Locale (Locale : System.Address) return System.Address
      with Import, Convention => C, External_Name => "uselocale";
   procedure Free_Locale (Locale : System.Address)
      with Import, Convention => C, External_Name => "freelocale";
   function Open_FD (A : System.Address; FD : int; Block_Size : size_t) return int with Import, Convention => C, External_Name => "archive_read_open_fd";
   function Next_Header (A : System.Address; E : access System.Address) return int with Import, Convention => C, External_Name => "archive_read_next_header";
   function Read_Data (A, B : System.Address; Size : size_t) return long with Import, Convention => C, External_Name => "archive_read_data";
   function Filter_Count (A : System.Address) return int with Import, Convention => C, External_Name => "archive_filter_count";
   function Filter_Code (A : System.Address; Index : int) return int with Import, Convention => C, External_Name => "archive_filter_code";
   function Filter_Bytes (A : System.Address; Index : int) return long_long with Import, Convention => C, External_Name => "archive_filter_bytes";
   function Archive_Format (A : System.Address) return int with Import, Convention => C, External_Name => "archive_format";
   function Pathname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_pathname";
   function Uname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_uname";
   function Gname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_gname";
   function Symlink (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_symlink";
   function Hardlink (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_hardlink";
   function Mode (E : System.Address) return unsigned with Import, Convention => C, External_Name => "archive_entry_mode";
   function Entry_Size (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_size";
   function UID (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_uid";
   function GID (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_gid";
   function Rdevmajor (E : System.Address) return unsigned_long with Import, Convention => C, External_Name => "archive_entry_rdevmajor";
   function Rdevminor (E : System.Address) return unsigned_long with Import, Convention => C, External_Name => "archive_entry_rdevminor";
   procedure Fflags (E : System.Address; Set, Clear : access unsigned_long) with Import, Convention => C, External_Name => "archive_entry_fflags";
   function Copy_Fflags (E : System.Address; Text : char_array) return chars_ptr
      with Import, Convention => C, External_Name => "archive_entry_copy_fflags_text";
   function Mtime (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_mtime";
   function Mtime_Nsec (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_mtime_nsec";
   function Mtime_Set (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_mtime_is_set";
   function Atime (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_atime";
   function Atime_Nsec (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_atime_nsec";
   function Atime_Set (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_atime_is_set";
   function Ctime (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_ctime";
   function Ctime_Nsec (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_ctime_nsec";
   function Ctime_Set (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_ctime_is_set";
   function Btime (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_birthtime";
   function Btime_Nsec (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_birthtime_nsec";
   function Btime_Set (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_birthtime_is_set";
   function Sparse_Count (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_sparse_count";
   function Encrypted (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_is_encrypted";
   function Xattr_Reset (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_xattr_reset";
   function Xattr_Next (E : System.Address; Name : access chars_ptr; Value : access System.Address; Size : access size_t) return int
      with Import, Convention => C, External_Name => "archive_entry_xattr_next";
   function ACL_Reset (E : System.Address; Types : int) return int with Import, Convention => C, External_Name => "archive_entry_acl_reset";
   function ACL_Next (E : System.Address; Types : int; ACL_Type, Permset, Tag, Qualifier : access int; Name : access chars_ptr) return int
      with Import, Convention => C, External_Name => "archive_entry_acl_next";
   function Strnlen (P : chars_ptr; N : size_t) return size_t with Import, Convention => C, External_Name => "strnlen";
   procedure Memcpy (Destination, Source : System.Address; Size : size_t) with Import, Convention => C, External_Name => "memcpy";
   procedure Bounded (P : chars_ptr; Text : out Unbounded_String; Status : out Outcome) is
      N : size_t;
   begin
      Text := Null_Unbounded_String; Status := OK;
      if P = Null_Ptr then return; end if;
      N := Strnlen (P, Max_Name + 1);
      if N > Max_Name then Status := Exhausted; return; end if;
      Text := To_Unbounded_String (Value (P, N));
   end Bounded;
   function Path (Raw : String; Directory : Boolean; Valid : out Boolean) return String is
      First : Positive := Raw'First; Last : Natural := Raw'Last; Start : Positive;
   begin
      Valid := False;
      if Directory and then Raw in "." | "./" then Valid := True; return ""; end if;
      if Raw'Length > 2 and then Raw (Raw'First .. Raw'First + 1) = "./" then First := First + 2; end if;
      if Directory then while Last >= First and then Raw (Last) = '/' loop Last := Last - 1; end loop; end if;
      if Last < First or else Raw (First) = '/' then return ""; end if;
      Start := First;
      for I in First .. Last + 1 loop
         if I = Last + 1 or else Raw (I) = '/' then
            if I = Start or else I - Start > 255 or else Raw (Start .. I - 1) in "." | ".." then return ""; end if;
            Start := I + 1;
         elsif Raw (I) = ASCII.NUL then return "";
         end if;
      end loop;
      Valid := True; return Raw (First .. Last);
   end Path;
   function Link_Contained (Name, Target : String) return Boolean is
      Depth : Natural := 0; Start : Positive := Target'First;
   begin
      if Target'Length = 0 then return False; end if;
      if Target (Target'First) /= '/' then for C of Name loop if C = '/' then Depth := Depth + 1; end if; end loop; end if;
      for I in Target'First .. Target'Last + 1 loop
         if I = Target'Last + 1 or else Target (I) = '/' then
            if Target (Start .. I - 1) = ".." then
               if Depth = 0 then return False; end if; Depth := Depth - 1;
            elsif I > Start and then Target (Start .. I - 1) /= "." then Depth := Depth + 1; end if;
            Start := I + 1;
         elsif Target (I) = ASCII.NUL then return False;
         end if;
      end loop;
      return True;
   end Link_Contained;
   procedure Clock_Value (Present : int; Seconds, Nanoseconds : long; Value : out Timestamp; Status : out Outcome) is
      Sec : Interfaces.Integer_64 := Interfaces.Integer_64 (Seconds); Nsec : long := Nanoseconds;
   begin
      Value := (others => <>); Status := OK; if Present = 0 then return; end if;
      if Nsec not in -999_999_999 .. 999_999_999 then Status := Unsupported; return; end if;
      if Nsec < 0 then
         if Sec = Interfaces.Integer_64'First then Status := Unsupported; return; end if;
         Sec := Sec - 1; Nsec := Nsec + 1_000_000_000;
      end if;
      Value := (True, Sec, Natural (Nsec));
   end Clock_Value;
   procedure Stage (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
                    Result : in out Inventory; Status : out Outcome) is
      Candidate : Data_Access;
      Envelope : Pkg_Deb_Container.Envelope; Stream : Pkg_Deb_Data_Stream.Observation;
      Frames : Pkg_Tar_Framing.Index; Frame : Pkg_Tar_Framing.Frame;
      F : MC_FS.File; Before, After : MC_FS.Entry_Info; Writer : MC_Store.Writer;
      A : System.Address := System.Null_Address; E : aliased System.Address := System.Null_Address;
      Locale, Previous_Locale : System.Address := System.Null_Address;
      RC, Ignored : int; N : long; Position : Natural := 0; Now, Total : Counter := 0;
      Buffer : Bytes (1 .. 65_536); Item : Stored_Entry; Raw_Path : Unbounded_String;
      Flag_Set, Flag_Clear : aliased unsigned_long;
      Good : Boolean;
      pragma Unreferenced (Ignored);
      procedure Release_Resources is
      begin
         MC_Store.Abort_Write (Writer);
         if A /= System.Null_Address then Ignored := Free_Archive (A); A := System.Null_Address; end if;
         if Previous_Locale /= System.Null_Address then
            declare Restored : constant System.Address := Use_Locale (Previous_Locale); begin
               if Restored = System.Null_Address then Status := IO_Error; end if;
            end;
            Previous_Locale := System.Null_Address;
         end if;
         if Locale /= System.Null_Address then Free_Locale (Locale); Locale := System.Null_Address; end if;
         MC_FS.Close (F);
      end Release_Resources;
      procedure Cleanup is
      begin Release_Resources; Free (Candidate); end Cleanup;
      procedure Check_Time is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
      procedure Attributes_To_CAS is
         type Xattr is record Name : Unbounded_String; Value : System.Address; Size : size_t; end record;
         List : array (1 .. 64) of Xattr; Temp : Xattr;
         Blob : Bytes (1 .. MC_FS.Max_Xattr_Bytes); P, Used : Natural;
         Count, Got : int; Name : aliased chars_ptr; Address : aliased System.Address; Size : aliased size_t;
         ACL_Type, Permset, Tag, Qualifier : aliased int;
      begin
         Count := Xattr_Reset (E);
         if Count < 0 or else Count > List'Length then Status := Exhausted; return; end if;
         for I in 1 .. Natural (Count) loop
            Got := Xattr_Next (E, Name'Access, Address'Access, Size'Access);
            if Got /= 0 or else (Address = System.Null_Address and then Size > 0) then Status := Corrupt; return; end if;
            Bounded (Name, List (I).Name, Status); if Status /= OK then return; end if;
            if Length (List (I).Name) not in 1 .. 255 or else Size > 65_536 then Status := Exhausted; return; end if;
            List (I).Value := Address; List (I).Size := Size;
         end loop;
         for I in 1 .. Natural (Count) loop
            for J in I + 1 .. Natural (Count) loop
               if To_String (List (J).Name) < To_String (List (I).Name) then Temp := List (I); List (I) := List (J); List (J) := Temp; end if;
            end loop;
         end loop;
         Blob := (others => 0); MC_Codec.Put16 (Blob, 1, Natural (Count)); P := 2;
         for I in 1 .. Natural (Count) loop
            if I > 1 and then List (I).Name = List (I - 1).Name then Status := Unsupported; return; end if;
            Used := Length (List (I).Name);
            if 6 + Used + Natural (List (I).Size) > Blob'Length - P then Status := Exhausted; return; end if;
            MC_Codec.Put16 (Blob, P + 1, Used); MC_Codec.Put32 (Blob, P + 3, Word (List (I).Size)); P := P + 6;
            for C of To_String (List (I).Name) loop P := P + 1; Blob (P) := Character'Pos (C); end loop;
            if List (I).Size > 0 then Memcpy (Blob (P + 1)'Address, List (I).Value, List (I).Size); end if;
            P := P + Natural (List (I).Size);
         end loop;
         MC_Store.Put (Store, Blob (1 .. P), Item.Values.Xattrs, Status); if Status /= OK then return; end if;
         Count := ACL_Reset (E, 16#3F00#);
         if Count < 0 or else Count > 1024 then Status := Exhausted; return; end if;
         Blob := (others => 0); MC_Codec.Put16 (Blob, 1, Natural (Count)); P := 2;
         for I in 1 .. Natural (Count) loop
            Got := ACL_Next (E, 16#3F00#, ACL_Type'Access, Permset'Access, Tag'Access, Qualifier'Access, Name'Access);
            if Got /= 0 then Status := Corrupt; return; end if;
            declare Text : Unbounded_String; begin
               Bounded (Name, Text, Status); if Status /= OK then return; end if; Used := Length (Text);
               if Used + 18 > Blob'Length - P then Status := Exhausted; return; end if;
               MC_Codec.Put32 (Blob, P + 1, Word (ACL_Type)); MC_Codec.Put32 (Blob, P + 5, Word (Permset));
               MC_Codec.Put32 (Blob, P + 9, Word (Tag)); MC_Codec.Put32 (Blob, P + 13, Word'Mod (Qualifier));
               MC_Codec.Put16 (Blob, P + 17, Used); P := P + 18;
               for C of To_String (Text) loop P := P + 1; Blob (P) := Character'Pos (C); end loop;
            end;
         end loop;
         MC_Store.Put (Store, Blob (1 .. P), Item.Values.ACLs, Status);
      end Attributes_To_CAS;
      procedure Content_To_CAS is
         Hash : MC_SHA256.Context := MC_SHA256.Initialize;
         Read_Count : Natural; Written : Counter := 0;
      begin
         loop
            Check_Time; if Status /= OK then return; end if;
            N := Read_Data (A, Buffer'Address, Buffer'Length);
            if N < 0 or else N > Buffer'Length then Status := Corrupt; return; end if;
            exit when N = 0;
            if Counter (N) > Frame.Size - Written then Status := Corrupt; return; end if;
            Written := Written + Counter (N); MC_SHA256.Update (Hash, Buffer (1 .. Natural (N)));
         end loop;
         if Written /= Frame.Size then Status := Corrupt; return; end if;
         Item.Values.Content := MC_SHA256.Finish (Hash); Item.Values.Content_Size := Written;
         MC_Store.Begin_Write (Store, Item.Values.Content, Written, Writer, Status); if Status /= OK then return; end if;
         Written := 0;
         while Written < Frame.Size loop
            Check_Time; if Status /= OK then return; end if;
            Read_Count := Natural (Counter'Min (Counter (Buffer'Length), Frame.Size - Written));
            MC_FS.Read_At (F, Frame.Body_Start + Written, Buffer (1 .. Read_Count), Read_Count, Status); if Status /= OK then return; end if;
            if Read_Count = 0 then Status := Corrupt; return; end if;
            MC_Store.Write_Chunk (Writer, Buffer (1 .. Read_Count), Status); if Status /= OK then return; end if;
            Written := Written + Counter (Read_Count);
         end loop;
         MC_Store.Finish_Write (Store, Writer, Status);
      end Content_To_CAS;
      procedure Resolve_Links is
         type Stamp_Array is array (Positive range <>) of Natural;
         type Stamp_Access is access Stamp_Array;
         procedure Free is new Ada.Unchecked_Deallocation (Stamp_Array, Stamp_Access);
         Seen : Stamp_Access := new Stamp_Array (1 .. Natural (Candidate.Entries.Length));
         Walk : Positions.Vector; At_Node, Target : Natural; Node, Base : Stored_Entry;
      begin
         Seen.all := (others => 0);
         for I in 1 .. Natural (Candidate.Entries.Length) loop
            Check_Time; if Status /= OK then Free (Seen); return; end if;
            Node := Candidate.Entries.Element (I);
            declare Name : constant String := To_String (Node.Path); begin
               for J in Name'Range loop
                  if Name (J) = '/' and then Candidate.By_Name.Contains (Name (Name'First .. J - 1)) then
                     Target := Candidate.By_Name.Element (Name (Name'First .. J - 1));
                     if Candidate.Entries.Element (Target).Values.Kind /= Directory then Status := Corrupt; Free (Seen); return; end if;
                  end if;
               end loop;
            end;
            if Node.Values.Kind = Hard_Link and then Node.Values.Inode_Entry = 0 then
               Walk.Clear; At_Node := I;
               loop
                  Check_Time; if Status /= OK then Free (Seen); return; end if;
                  if Seen (At_Node) = I then Status := Corrupt; Free (Seen); return; end if;
                  Seen (At_Node) := I; Node := Candidate.Entries.Element (At_Node);
                  exit when Node.Values.Inode_Entry /= 0;
                  if Node.Values.Kind /= Hard_Link or else not Candidate.By_Name.Contains (To_String (Node.Link_Target)) then
                     Status := Corrupt; Free (Seen); return;
                  end if;
                  Walk.Append (At_Node); At_Node := Candidate.By_Name.Element (To_String (Node.Link_Target));
               end loop;
               Base := Candidate.Entries.Element (Node.Values.Inode_Entry);
               if Base.Values.Kind /= Regular then Status := Unsupported; Free (Seen); return; end if;
               for Index of Walk loop
                  Node := Candidate.Entries.Element (Index); Node.Values.Inode_Entry := Base.Values.Inode_Entry;
                  Node.Values.Content := Base.Values.Content; Node.Values.Content_Size := Base.Values.Content_Size;
                  Candidate.Entries.Replace_Element (Index, Node);
               end loop;
            end if;
         end loop;
         Free (Seen);
      exception when others => Free (Seen); raise;
      end Resolve_Links;
   begin
      Clear (Result); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Check_Time; if Status /= OK then return; end if;
      Pkg_Deb_Container.Inspect (Store, Original, Deadline, Envelope, Status); if Status /= OK then return; end if;
      Pkg_Deb_Data_Stream.Stage (Store, Envelope, MC_Store.Max_Object_Size, Deadline, Stream, Status); if Status /= OK then return; end if;
      MC_Store.Open_Object (Store, Stream.Expanded, F, Status); if Status /= OK then Cleanup; return; end if;
      MC_FS.Info (F, Before, Status); if Status /= OK then Cleanup; return; end if;
      if Before.Size /= Stream.Expanded_Size then Status := Corrupt; Cleanup; return; end if;
      Pkg_Tar_Framing.Scan (F, Before.Size, Deadline, Frames, Status); if Status /= OK then Cleanup; return; end if;
      Candidate := new Data; Candidate.Original := Original; Candidate.Tar := Stream.Expanded;
      -- Linux LC_CTYPE_MASK = 1. Use a fixed, thread-local decoding locale;
      -- restore the caller's locale on every exit without global setlocale.
      Locale := New_Locale (1, To_C ("C.UTF-8"), System.Null_Address);
      if Locale = System.Null_Address then Status := Unsupported; Cleanup; return; end if;
      Previous_Locale := Use_Locale (Locale);
      if Previous_Locale = System.Null_Address then Status := IO_Error; Cleanup; return; end if;
      A := New_Archive;
      if A = System.Null_Address then Status := Exhausted; Cleanup; return; end if;
      if Format_Tar (A) /= 0
         or else Open_FD (A, int (MC_FS.Native (F)), 65_536) /= 0 then Status := Corrupt; Cleanup; return; end if;
      if Filter_Count (A) /= 1 or else Filter_Code (A, 0) /= 0 then Status := Corrupt; Cleanup; return; end if;
      loop
         Check_Time; if Status /= OK then Cleanup; return; end if;
         RC := Next_Header (A, E'Access); exit when RC = 1;
         if RC /= 0 or else E = System.Null_Address then Status := Corrupt; Cleanup; return; end if;
         if Archive_Format (A) not in 16#30000# .. 16#30004# or else Sparse_Count (E) /= 0 or else Encrypted (E) /= 0 then
            Status := Unsupported; Cleanup; return;
         end if;
         Position := Position + 1;
         if Position > Pkg_Tar_Framing.Count (Frames) then Status := Corrupt; Cleanup; return; end if;
         Frame := Pkg_Tar_Framing.At_Index (Frames, Position);
         if Filter_Bytes (A, 0) < 0 or else Counter (Filter_Bytes (A, 0)) /= Frame.Body_Start
            or else Entry_Size (E) < 0 or else Counter (Entry_Size (E)) /= Frame.Size then Status := Corrupt; Cleanup; return; end if;
         Item := (others => <>);
         if Hardlink (E) /= Null_Ptr then
            Item.Values.Kind := Hard_Link; Bounded (Hardlink (E), Item.Link_Target, Status); if Status /= OK then Cleanup; return; end if;
            if Length (Frame.Names (2)) > 0 then Item.Link_Target := Frame.Names (2); end if;
            Item.Link_Target := To_Unbounded_String (Path (To_String (Item.Link_Target), False, Good));
            if not Good then Status := Corrupt; Cleanup; return; end if;
         else
            case Word (Mode (E)) and 8#170000# is
               when 8#100000# => Item.Values.Kind := Regular;
               when 8#040000# => Item.Values.Kind := Directory;
               when 8#120000# => Item.Values.Kind := Symbolic_Link;
               when 8#020000# => Item.Values.Kind := Character_Device;
               when 8#060000# => Item.Values.Kind := Block_Device;
               when 8#010000# => Item.Values.Kind := FIFO;
               when others => Status := Unsupported; Cleanup; return;
            end case;
         end if;
         Bounded (Pathname (E), Raw_Path, Status); if Status /= OK then Cleanup; return; end if;
         -- Linux filenames are byte identities. Retain local PAX name bytes
         -- instead of the library's Unicode-normalized representation.
         if Length (Frame.Names (1)) > 0 then Raw_Path := Frame.Names (1); end if;
         Item.Path := To_Unbounded_String (Path (To_String (Raw_Path), Item.Values.Kind = Directory, Good));
         if not Good or else Candidate.By_Name.Contains (To_String (Item.Path)) then Status := Corrupt; Cleanup; return; end if;
         Bounded (Uname (E), Item.User_Name, Status); if Status /= OK then Cleanup; return; end if;
         Bounded (Gname (E), Item.Group_Name, Status); if Status /= OK then Cleanup; return; end if;
         if Length (Frame.Names (3)) > 0 then Item.User_Name := Frame.Names (3); end if;
         if Length (Frame.Names (4)) > 0 then Item.Group_Name := Frame.Names (4); end if;
         if UID (E) < 0 or else UID (E) > long_long (Word'Last) or else GID (E) < 0 or else GID (E) > long_long (Word'Last)
            or else Rdevmajor (E) > unsigned_long (Word'Last) or else Rdevminor (E) > unsigned_long (Word'Last) then Status := Unsupported; Cleanup; return; end if;
         Item.Values.Mode := Word (Mode (E)) and 8#7777#; Item.Values.UID := Word (UID (E)); Item.Values.GID := Word (GID (E));
         Item.Values.Device_Major := Word (Rdevmajor (E)); Item.Values.Device_Minor := Word (Rdevminor (E));
         Item.Values.Archive_Size := Frame.Size;
         Clock_Value (Mtime_Set (E), Mtime (E), Mtime_Nsec (E), Item.Values.Modified, Status); if Status /= OK then Cleanup; return; end if;
         Clock_Value (Atime_Set (E), Atime (E), Atime_Nsec (E), Item.Values.Accessed, Status); if Status /= OK then Cleanup; return; end if;
         Clock_Value (Ctime_Set (E), Ctime (E), Ctime_Nsec (E), Item.Values.Changed, Status); if Status /= OK then Cleanup; return; end if;
         Clock_Value (Btime_Set (E), Btime (E), Btime_Nsec (E), Item.Values.Created, Status); if Status /= OK then Cleanup; return; end if;
         -- Keep exact decimal PAX times, including negative fractions that the
         -- pinned library interprets differently. No upstream source changes.
         if Frame.Clocks (1).Present then Item.Values.Modified := Frame.Clocks (1); end if;
         if Frame.Clocks (2).Present then Item.Values.Accessed := Frame.Clocks (2); end if;
         if Frame.Clocks (3).Present then Item.Values.Changed := Frame.Clocks (3); end if;
         if Frame.Clocks (4).Present then Item.Values.Created := Frame.Clocks (4); end if;
         if Length (Frame.Flags) > 0 and then Copy_Fflags (E, To_C (To_String (Frame.Flags))) /= Null_Ptr then
            Status := Unsupported; Cleanup; return;
         end if;
         Fflags (E, Flag_Set'Access, Flag_Clear'Access); Item.Values.Flags_Set := Wide (Flag_Set); Item.Values.Flags_Clear := Wide (Flag_Clear);
         Attributes_To_CAS; if Status /= OK then Cleanup; return; end if;
         case Item.Values.Kind is
            when Regular =>
               if Frame.Size > MC_Store.Max_Object_Size - Total then Status := Exhausted; Cleanup; return; end if;
               Total := Total + Frame.Size; Content_To_CAS; if Status /= OK then Cleanup; return; end if;
               Item.Values.Inode_Entry := Position;
            when Symbolic_Link =>
               Bounded (Symlink (E), Item.Link_Target, Status); if Status /= OK then Cleanup; return; end if;
               if Length (Frame.Names (2)) > 0 then Item.Link_Target := Frame.Names (2); end if;
               if not Link_Contained (To_String (Item.Path), To_String (Item.Link_Target)) then Status := Corrupt; Cleanup; return; end if;
               declare Text : constant String := To_String (Item.Link_Target); Blob : Bytes (1 .. Text'Length); begin
                  for I in Text'Range loop Blob (I) := Character'Pos (Text (I)); end loop;
                  MC_Store.Put (Store, Blob, Item.Values.Content, Status); if Status /= OK then Cleanup; return; end if;
                  Item.Values.Content_Size := Counter (Text'Length);
               end;
            when others => null;
         end case;
         declare Bytes : constant Natural := Length (Item.Path) + Length (Item.Link_Target) + Length (Item.User_Name) + Length (Item.Group_Name); begin
            if Bytes > Max_Names - Candidate.Name_Bytes then Status := Exhausted; Cleanup; return; end if;
            Candidate.Name_Bytes := Candidate.Name_Bytes + Bytes;
         end;
         Candidate.By_Name.Insert (To_String (Item.Path), Position); Candidate.Entries.Append (Item);
      end loop;
      if Position /= Pkg_Tar_Framing.Count (Frames) then Status := Corrupt; Cleanup; return; end if;
      Resolve_Links; if Status /= OK then Cleanup; return; end if;
      MC_FS.Info (F, After, Status); if Status /= OK then Cleanup; return; end if;
      if Before /= After then Status := Stale; Cleanup; return; end if;
      Check_Time; if Status /= OK then Cleanup; return; end if;
      Release_Resources;
      if Status = OK then Result.State := Candidate; Candidate := null;
      else Free (Candidate); end if;
   exception
      when Storage_Error => Cleanup; Clear (Result); Status := Exhausted;
      when others => Cleanup; Clear (Result); Status := IO_Error;
   end Stage;
end Pkg_Deb_Payload;
