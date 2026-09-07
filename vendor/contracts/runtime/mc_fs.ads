-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Text; with MC_Dirents;
package MC_FS with SPARK_Mode => Off is
   type Root is limited private;
   type File is limited private;
   type Entry_Kind is (Absent, Regular, Directory, Symbolic_Link, Other);
   type Entry_Info is record
      Kind : Entry_Kind := Absent;
      Mode, UID, GID, Links : Word := 0;
      Size : Counter := 0;
      Inode, Mount_ID : Wide := 0;
      Device_Major, Device_Minor : Word := 0;
      Mtime_Sec : Counter := 0;
      Mtime_Nsec : Natural range 0 .. 999_999_999 := 0;
      Ctime_Sec : Counter := 0;
      Ctime_Nsec : Natural range 0 .. 999_999_999 := 0;
      -- Change time is observation evidence, not a restorable file attribute.
      -- Equality detects an in-place rewrite even if the writer restores mtime.
      -- Still requires the single-writer reservation; not a malicious-root proof.
   end record;
   procedure Open_Root (Path : String; R : in out Root; Status : out Outcome;
                        Private_Only : Boolean := False);
   procedure List_Names (R : Root; Path : String; Names : out MC_Dirents.Listing; Status : out Outcome);
   -- Bounded complete directory scan, sorted names including links/special names.
   -- Empty Path means the root. Does NOT follow entries or infer their type.
   -- Caller must hold the configuration writer reservation and re-observe before use.
   procedure Root_Info (R : Root; Info : out Entry_Info; Status : out Outcome);
   procedure Stat (R : Root; Path : String; Info : out Entry_Info; Status : out Outcome);
   procedure Open_Read (R : Root; Path : String; F : in out File; Status : out Outcome);
   procedure Create_New (R : Root; Path : String; F : in out File; Status : out Outcome);
   procedure Open_Locked (R : Root; Path : String; F : in out File; Status : out Outcome;
                          Create_If_Missing : Boolean := True);
   -- Recovery must set Create_If_Missing => False. A missing record is not a
   -- newly provisioned empty state. Existing special files must never block open.
   procedure Info (F : File; Value : out Entry_Info; Status : out Outcome);
   procedure Read_At (F : File; Offset : Counter; Data : out Bytes;
                      Count : out Natural; Status : out Outcome);
   procedure Write_All (F : in out File; Data : Bytes; Status : out Outcome);
   procedure Append_Durable (F : in out File; Expected_Length : Counter;
                              Data : Bytes; Status : out Outcome);
   procedure Sync (F : File; Status : out Outcome);
   procedure Sync_Parent (R : Root; Path : String; Status : out Outcome);
   procedure Hash (F : File; Limit : Counter; D : out Digest; Size : out Counter; Status : out Outcome);
   procedure Make_Directory (R : Root; Path : String; Status : out Outcome);
   procedure Read_Link (R : Root; Path : String; Target : out MC_Text.Value; Status : out Outcome);
   procedure Make_Link (R : Root; Path, Target : String; Status : out Outcome);
   procedure Rename (R : Root; From_Path, To_Path : String;
                      No_Replace : Boolean; Status : out Outcome);
   procedure Remove (R : Root; Path : String; Is_Directory : Boolean; Status : out Outcome);
   procedure Set_Metadata (F : File; Value : Entry_Info; Status : out Outcome);
   procedure Set_Link_Owner (R : Root; Path : String; UID, GID : Word; Status : out Outcome);
   Max_Xattr_Bytes : constant := 131_072;
   procedure Get_Xattrs (F : File; Data : out Bytes; Used : out Natural; Status : out Outcome);
   procedure Set_Xattrs (F : File; Data : Bytes; Status : out Outcome);
   procedure Get_Link_Xattrs (R : Root; Path : String; Data : out Bytes;
                              Used : out Natural; Status : out Outcome);
   procedure Set_Link_Xattrs (R : Root; Path : String; Data : Bytes; Status : out Outcome);
   procedure Close (F : in out File);
   procedure Close (R : in out Root);
   function Native (F : File) return Integer;
   -- All relative traversal uses openat2(NO_XDEV|BENEATH|NO_SYMLINKS|NO_MAGICLINKS).
   -- No fallback if openat2 or STATX_MNT_ID is unavailable. No untrusted shell.
   -- Caller owns a single-writer reservation. Parent directories cannot be modified
   -- by non-owner accounts. Privileged/owner out-of-band mutation is outside the model.
private
   type Root is limited record
      Handle : Integer := -1;
      Identity : Entry_Info;
   end record;
   type File is limited record
      Handle : Integer := -1;
      Writable, Poisoned : Boolean := False;
   end record;
end MC_FS;
