-- SPDX-License-Identifier: MIT
with Ada.Finalization;
with Ada.Strings.Bounded;
with MC_Types; use MC_Types;
with MC_Store;
with Pkg_Tar_Framing;
package Pkg_Deb_Payload with SPARK_Mode => Off is
   Max_Name : constant := 4096;
   package Byte_Strings is new Ada.Strings.Bounded.Generic_Bounded_Length (Max_Name);
   Max_Entries : constant := 131_072;
   Max_Names : constant := 64 * 1024 * 1024;
   type Entry_Kind is (Regular, Directory, Symbolic_Link, Hard_Link, Character_Device, Block_Device, FIFO);
   subtype Timestamp is Pkg_Tar_Framing.Timestamp;
   type Attributes is record
      Kind : Entry_Kind := Regular;
      Mode, UID, GID, Device_Major, Device_Minor : Word := 0;
      Modified, Accessed, Changed, Created : Timestamp;
      Archive_Size, Content_Size : Counter := 0;
      Content, Xattrs, ACLs : Digest := Zero_Digest;
      Flags_Set, Flags_Clear : Wide := 0;
      Inode_Entry : Natural := 0;
   end record;
   type Payload_Entry is record
      Path, Link_Target, User_Name, Group_Name : Byte_Strings.Bounded_String;
      Values : Attributes;
   end record;
   type Inventory is new Ada.Finalization.Limited_Controlled with private;
   procedure Stage (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
                    Result : in out Inventory; Status : out Outcome);
   procedure Clear (Value : in out Inventory);
   function Count (Value : Inventory) return Natural;
   function Original_Hash (Value : Inventory) return Digest;
   function Tar_Hash (Value : Inventory) return Digest;
   function Find (Value : Inventory; Path : String) return Natural;
   procedure Read_Entry (Value : Inventory; Position : Positive; Item : out Payload_Entry; Status : out Outcome);
   -- Complete bounded observation and CAS content retention before publishing
   -- the private inventory. No archive extraction, scripts or installed catalog.
   -- Paths and link text retain bytes; Unicode interpretation belongs to the UI.
   -- Parent kinds, duplicate paths and complete hardlink graphs are checked.
   -- All permission bits, numeric and symbolic ownership, clocks, xattrs, ACLs
   -- and device metadata are retained. They are not authority to apply them.
   -- Existing generation file plans cannot express every retained attribute;
   -- callers must not truncate this inventory to that older execution profile.
   -- UID 0 is refused; process resource and time limits are still required.
private
   type Data;
   type Data_Access is access Data;
   type Inventory is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Inventory);
end Pkg_Deb_Payload;
