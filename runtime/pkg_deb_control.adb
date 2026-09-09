-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation;
with Interfaces.C; with Interfaces.C.Strings; with System;
with MC_FS; with MC_Clock; with MC_Posix; with MC_SHA256;
package body Pkg_Deb_Control with SPARK_Mode => Off is
   use Interfaces.C; use Interfaces.C.Strings; use type System.Address;
   use type MC_FS.Entry_Info; use type Pkg_Deb_Container.Member_Kind;
   use type Word;
   function New_Archive return System.Address with Import, Convention => C, External_Name => "archive_read_new";
   function Free_Archive (A : System.Address) return int with Import, Convention => C, External_Name => "archive_read_free";
   function Close_Archive (A : System.Address) return int with Import, Convention => C, External_Name => "archive_read_close";
   function Decode (Codec : int; Input : System.Address; Input_Size : size_t;
                    Output : System.Address; Capacity : size_t; Used : access size_t;
                    Deadline : Interfaces.Unsigned_64) return int
      with Import, Convention => C, External_Name => "nia_deb_decode";
   function Open_Memory (A, Data : System.Address; Size : size_t) return int
      with Import, Convention => C, External_Name => "archive_read_open_memory";
   function Format_Tar (A : System.Address) return int with Import, Convention => C, External_Name => "archive_read_support_format_tar";
   function Filter_Code (A : System.Address; Index : int) return int with Import, Convention => C, External_Name => "archive_filter_code";
   function Filter_Count (A : System.Address) return int with Import, Convention => C, External_Name => "archive_filter_count";
   function Filter_Bytes (A : System.Address; Index : int) return long_long with Import, Convention => C, External_Name => "archive_filter_bytes";
   function Archive_Format (A : System.Address) return int with Import, Convention => C, External_Name => "archive_format";
   function Next_Header (A : System.Address; E : access System.Address) return int with Import, Convention => C, External_Name => "archive_read_next_header";
   function Read_Data (A, B : System.Address; Size : size_t) return long with Import, Convention => C, External_Name => "archive_read_data";
   function Pathname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_pathname";
   function Uname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_uname";
   function Gname (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_gname";
   function Symlink (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_symlink";
   function Hardlink (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_hardlink";
   function Flags_Text (E : System.Address) return chars_ptr with Import, Convention => C, External_Name => "archive_entry_fflags_text";
   function Mode (E : System.Address) return unsigned with Import, Convention => C, External_Name => "archive_entry_mode";
   function Size (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_size";
   function UID (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_uid";
   function GID (E : System.Address) return long_long with Import, Convention => C, External_Name => "archive_entry_gid";
   function Mtime (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_mtime";
   function Mtime_Nsec (E : System.Address) return long with Import, Convention => C, External_Name => "archive_entry_mtime_nsec";
   function Sparse_Count (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_sparse_count";
   function Xattr_Count (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_xattr_count";
   function ACL_Count (E : System.Address; Types : int) return int with Import, Convention => C, External_Name => "archive_entry_acl_count";
   function Encrypted (E : System.Address) return int with Import, Convention => C, External_Name => "archive_entry_is_encrypted";
   function Strnlen (P : chars_ptr; N : size_t) return size_t with Import, Convention => C, External_Name => "strnlen";
   procedure Bounded (P : chars_ptr; Result : out MC_Text.Value; Status : out Outcome) is
      N : size_t;
   begin
      Result := MC_Text.Empty;
      if P = Null_Ptr then Status := OK; return; end if;
      N := Strnlen (P, MC_Text.Max_Length + 1);
      if N > MC_Text.Max_Length then Status := Exhausted; return; end if;
      MC_Text.Set (Result, Value (P, N), Status);
   end Bounded;
   procedure Stage (Store : in out MC_Store.Store;
                    Expected : Pkg_Deb_Container.Envelope; Deadline : Counter;
                    Result : out Inventory; Status : out Outcome) is
      A : System.Address := System.Null_Address;
      E : aliased System.Address := System.Null_Address;
      F : MC_FS.File; Before, After : MC_FS.Entry_Info;
      Candidate : Inventory; Item : Control_Entry; Raw_Name : MC_Text.Value;
      Codec, RC, Ignored : int; N : long; Now : Counter; Used : Natural;
      type Buffer_Access is access Bytes;
      procedure Release is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Buffer, Encoded, Expanded : Buffer_Access;
      Encoded_Size : Natural; Expanded_Size : aliased size_t := 0;
      Scratch : Bytes (1 .. 65_536);
      pragma Unreferenced (Ignored);
      procedure Cleanup is
      begin
         if A /= System.Null_Address then Ignored := Free_Archive (A); A := System.Null_Address; end if;
         MC_FS.Close (F); Release (Buffer); Release (Encoded); Release (Expanded);
      end Cleanup;
      procedure Limits is
         Expanded : long_long;
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status /= OK then return; end if;
         if Now >= Deadline then Status := Stale; return; end if;
         Expanded := Filter_Bytes (A, 0);
         if Expanded < 0 then Status := Corrupt;
         elsif Counter (Expanded) > Max_Tar_Bytes then Status := Exhausted; end if;
      end Limits;
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      if Expected.Control_Index = 0 or else Expected.Control_Index > Expected.Count
         or else Expected.Items (Expected.Control_Index).Kind /= Pkg_Deb_Container.Control_Archive then
         Status := Invalid_Input; return;
      end if;
      Pkg_Deb_Container.Stage_Member (Store, Expected, Expected.Control_Index, Deadline, Candidate.Archive, Status);
      if Status /= OK then return; end if;
      Candidate.Original := Expected.Original;
      MC_Store.Open_Object (Store, Candidate.Archive, F, Status); if Status /= OK then Cleanup; return; end if;
      MC_FS.Info (F, Before, Status); if Status /= OK then Cleanup; return; end if;
      case Expected.Items (Expected.Control_Index).Codec is
         when Pkg_Deb_Container.Uncompressed => Codec := 0;
         when Pkg_Deb_Container.Gzip => Codec := 1;
         when Pkg_Deb_Container.XZ => Codec := 6;
         when Pkg_Deb_Container.Zstd => Codec := 14;
         when others => Status := Unsupported; Cleanup; return;
      end case;
      if Before.Size = 0 or else Before.Size > Pkg_Deb_Container.Max_Control then
         Status := Corrupt; Cleanup; return;
      end if;
      Encoded := new Bytes (1 .. Natural (Before.Size));
      MC_FS.Read_At (F, 0, Encoded.all, Encoded_Size, Status);
      if Status /= OK then Cleanup; return; end if;
      if Encoded_Size /= Encoded'Length or else MC_SHA256.Hash (Encoded.all) /= Candidate.Archive then
         Status := Corrupt; Cleanup; return;
      end if;
      Expanded := new Bytes (1 .. Natural (Max_Tar_Bytes) + 1);
      RC := Decode (Codec, Encoded (1)'Address, Encoded'Length, Expanded (1)'Address,
                    Expanded'Length, Expanded_Size'Access, Interfaces.Unsigned_64 (Deadline));
      Status := (case RC is when 0 => OK, when 1 => Corrupt, when 2 => Exhausted,
                 when 3 => Stale, when 4 => Unsupported, when others => IO_Error);
      if Status /= OK then Cleanup; return; end if;
      if Expanded_Size > size_t (Max_Tar_Bytes) then Status := Exhausted; Cleanup; return; end if;
      Release (Encoded);
      A := New_Archive;
      if A = System.Null_Address then Status := Exhausted; Cleanup; return; end if;
      if Format_Tar (A) /= 0 then Status := Unsupported; Cleanup; return; end if;
      -- No decompression filters are registered with the tar interpreter.
      if Open_Memory (A, Expanded (1)'Address, Expanded_Size) /= 0 then Status := Corrupt; Cleanup; return; end if;
      if Filter_Count (A) /= 1 or else Filter_Code (A, 0) /= 0 then Status := Corrupt; Cleanup; return; end if;
      Buffer := new Bytes (1 .. Natural (Max_Contents));
      loop
         Limits; if Status /= OK then Cleanup; return; end if;
         RC := Next_Header (A, E'Access);
         Limits; if Status /= OK then Cleanup; return; end if;
         exit when RC = 1;
         if RC /= 0 or else E = System.Null_Address then Status := Corrupt; Cleanup; return; end if;
         if Archive_Format (A) not in 16#30000# | 16#30001# | 16#30004# then
            Status := Unsupported; Cleanup; return;
         end if;
         if Candidate.Count = Max_Entries then Status := Exhausted; Cleanup; return; end if;
         if Hardlink (E) /= Null_Ptr or else Symlink (E) /= Null_Ptr or else Sparse_Count (E) /= 0
            or else Xattr_Count (E) /= 0 or else ACL_Count (E, 16#3F00#) /= 0
            or else Flags_Text (E) /= Null_Ptr or else Encrypted (E) /= 0 then
            Status := Unsupported; Cleanup; return;
         end if;
         Item := (others => <>);
         Bounded (Pathname (E), Raw_Name, Status); if Status /= OK then Cleanup; return; end if;
         declare
            Raw : constant String := MC_Text.Image (Raw_Name);
            Name : constant String := (if Raw = "./" then "."
               elsif Raw'Length > 2 and then Raw (1 .. 2) = "./" then Raw (3 .. Raw'Last) else Raw);
         begin
            if Name = "." then
               if (Word (Mode (E)) and 8#170000#) /= 8#040000# or else Size (E) /= 0 then
                  Status := Unsupported; Cleanup; return;
               end if;
               Item.Kind := Directory;
            else
               if Name'Length = 0 or else Name = ".." or else (Word (Mode (E)) and 8#170000#) /= 8#100000# then
                  Status := Unsupported; Cleanup; return;
               end if;
               for C of Name loop
                  if C not in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '-' | '.' then
                     Status := Unsupported; Cleanup; return;
                  end if;
               end loop;
            end if;
            for I in 1 .. Candidate.Count loop
               if MC_Text.Image (Candidate.Entries (I).Name) = Name then Status := Corrupt; Cleanup; return; end if;
            end loop;
            MC_Text.Set (Item.Name, Name, Status); if Status /= OK then Cleanup; return; end if;
            if Name = "control" then Candidate.Control_Index := Candidate.Count + 1; end if;
         end;
         if UID (E) < 0 or else UID (E) > long_long (Word'Last) or else GID (E) < 0 or else GID (E) > long_long (Word'Last)
            or else Mtime_Nsec (E) not in 0 .. 999_999_999 then Status := Unsupported; Cleanup; return; end if;
         Item.UID := Word (UID (E)); Item.GID := Word (GID (E)); Item.Mode := Word (Mode (E)) and 8#7777#;
         Item.Modified_Seconds := Interfaces.Integer_64 (Mtime (E)); Item.Modified_Nanoseconds := Natural (Mtime_Nsec (E));
         Bounded (Uname (E), Item.User_Name, Status); if Status /= OK then Cleanup; return; end if;
         Bounded (Gname (E), Item.Group_Name, Status); if Status /= OK then Cleanup; return; end if;
         if Size (E) < 0 then Status := Corrupt; Cleanup; return; end if;
         Item.Size := Counter (Size (E));
         if Item.Size > Max_Contents - Candidate.Total_Contents then Status := Exhausted; Cleanup; return; end if;
         Used := 0;
         loop
            Limits; if Status /= OK then Cleanup; return; end if;
            N := Read_Data (A, Scratch'Address, Scratch'Length);
            if N < 0 or else N > long (Scratch'Length) then Status := Corrupt; Cleanup; return; end if;
            exit when N = 0;
            if Counter (N) > Item.Size - Counter (Used) then Status := Corrupt; Cleanup; return; end if;
            Buffer (Used + 1 .. Used + Natural (N)) := Scratch (1 .. Natural (N)); Used := Used + Natural (N);
         end loop;
         if Counter (Used) /= Item.Size then Status := Corrupt; Cleanup; return; end if;
         Limits; if Status /= OK then Cleanup; return; end if;
         if Item.Kind = Regular then
            MC_Store.Put (Store, Buffer (1 .. Used), Item.Content, Status); if Status /= OK then Cleanup; return; end if;
         end if;
         Candidate.Total_Contents := Candidate.Total_Contents + Item.Size;
         Candidate.Count := Candidate.Count + 1; Candidate.Entries (Candidate.Count) := Item;
      end loop;
      if Candidate.Control_Index = 0 then Status := Corrupt; Cleanup; return; end if;
      if Close_Archive (A) /= 0 then Status := Corrupt; Cleanup; return; end if;
      MC_FS.Info (F, After, Status); if Status /= OK then Cleanup; return; end if;
      if Before /= After then Status := Conflict; Cleanup; return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
      if Status = OK then Result := Candidate; end if;
      Cleanup;
   exception when others => Cleanup; Result := (others => <>); Status := IO_Error;
   end Stage;
end Pkg_Deb_Control;
