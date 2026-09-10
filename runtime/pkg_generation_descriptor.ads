-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_File_Plan;
package Pkg_Generation_Descriptor with SPARK_Mode => Off is
   type Descriptor is record
      Root_ID, Stage_ID : Identity := Zero_Identity;
      Manifest, Catalog : Digest := Zero_Digest;
      Generation : Counter := 0;
      Previous : Digest := Zero_Digest;
   end record;
   Empty : constant Descriptor := (others => <>);
   subtype Frame is Bytes (1 .. 192);
   function Valid (D : Descriptor) return Boolean;
   function Encode (D : Descriptor) return Frame;
   procedure Decode (B : Bytes; D : out Descriptor; Status : out Outcome);
   procedure Load (Store : MC_Store.Store; Hash : Digest; D : out Descriptor; Status : out Outcome);
   procedure Compile (Before, After : Descriptor; Transaction_ID : Identity;
      Epoch, Fence : Counter; Effect_Contract : Digest; UID, GID : Word;
      P : out Pkg_File_Plan.Plan; Status : out Outcome);
   procedure Check (Store : MC_Store.Store; P : Pkg_File_Plan.Plan;
      Before, After : out Descriptor; Status : out Outcome);
   function Stage_Path (Bank : String; D : Descriptor) return String;
   -- One canonical root/catalog binding and one fixed file-plan change.
   -- generation.next is UNPUBLISHED workspace: readers must use root.state's
   -- accepted plan and its CAS descriptor, never this pathname as an authority.
   -- Compile/Check validate framing and lineage, not catalog/effect semantics.
end Pkg_Generation_Descriptor;
