-- SPDX-License-Identifier: MIT
with Ada.Finalization;
with MC_Types; use MC_Types;
with Pkg_Deb_Payload;
package Pkg_Payload_Index with SPARK_Mode => Off is
   Max_Packages : constant := 4_096;
   Max_Claims : constant := 524_288;
   Max_Name_Bytes : constant := 256 * 1024 * 1024;
   type Index is new Ada.Finalization.Limited_Controlled with private;
   type Package_Source is record
      Original, Tar : Digest := Zero_Digest;
      Entries : Natural := 0;
   end record;
   type Claim is record
      Source : Package_Source;
      Source_Position : Natural := 0;
      Item : Pkg_Deb_Payload.Payload_Entry;
   end record;
   type Path_State is record
      First, Last : Natural := 0;
      All_Directories : Boolean := False;
      Same_Inode_Attributes : Boolean := False;
      Parent_Missing : Boolean := False;
      Non_Directory_Ancestor : Boolean := False;
   end record;
   procedure Add (Value : in out Index; Payload : Pkg_Deb_Payload.Inventory;
                  Deadline : Counter; Status : out Outcome);
   procedure Seal (Value : in out Index; Deadline : Counter; Status : out Outcome);
   procedure Clear (Value : in out Index);
   function Sealed (Value : Index) return Boolean;
   function Package_Count (Value : Index) return Natural;
   function Claim_Count (Value : Index) return Natural;
   function Path_Count (Value : Index) return Natural;
   function Fingerprint (Value : Index) return Digest;
   procedure Read_Package (Value : Index; Position : Positive;
                           Source : out Package_Source; Status : out Outcome);
   procedure Read_Claim (Value : Index; Position : Positive;
                         Item : out Claim; Status : out Outcome);
   procedure Read_Inode (Value : Index; Position : Positive;
                         Item : out Claim; Status : out Outcome);
   procedure Inspect_Path (Value : Index; Path : String;
                           State : out Path_State; Status : out Outcome);
   -- Private candidate-source index, never an installed catalog or write grant.
   -- Add accepts only complete native payload inventories. Claims are copied;
   -- clearing/reusing the source inventory cannot mutate this index.
   -- Seal orders sources by original digest and claims by raw path then source.
   -- Nothing is queryable before the complete seal. Any Add/Seal failure clears
   -- the candidate; callers restart collection instead of admitting a subset.
   -- Source entry ordinals identify hardlink inodes within one original DEB.
   -- Read_Claim retains the hardlink header, Read_Inode returns its base header.
   -- Every claim remains present, including differing shared-directory metadata.
   -- Missing parents and non-directory ancestors require namespace/effect policy;
   -- this layer neither invents directories nor follows links on the host.
   -- Package identity/version/architecture, Replaces, Multi-Arch, configuration,
   -- effects, root construction and admission remain catalog-layer obligations.
   -- No duplicate-original deduplication and no last-added-owner selection.
   -- Add and Seal refuse UID 0 and check deadlines. Outer resource limits apply.
private
   type Data;
   type Data_Access is access Data;
   type Index is new Ada.Finalization.Limited_Controlled with record
      State : Data_Access;
   end record;
   overriding procedure Finalize (Value : in out Index);
end Pkg_Payload_Index;
