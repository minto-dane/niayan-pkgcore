-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_System_Composition with SPARK_Mode, Pure is
   Capacity : constant := 4096;
   subtype Index is Positive range 1 .. Capacity;
   type Role is (User_Package, Kernel, Initramfs, Boot_Loader, Recovery_Image,
      Kernel_Module, Driver_Userspace, Service_Manager, C_Library);
   type Artifact is record
      Object_Digest, Payload, Distribution, Snapshot, Publisher, ABI, Target_Kernel,
        Driver_ABI : Digest := Zero_Digest;
      Kind : Role := User_Package;
      Trust_Epoch : Counter := 0;
      Signature_Admitted, Effects_Covered, Recovery_Pinned : Boolean := False;
   end record;
   type Artifact_List is array (Index) of Artifact;
   type Publisher_List is array (Positive range 1 .. 16) of Digest;
   type Composition is record
      Plan, Distribution, Snapshot : Digest := Zero_Digest;
      Count : Natural range 0 .. Capacity := 0;
      Artifacts : Artifact_List;
      Publishers : Publisher_List := (others => Zero_Digest);
      Publisher_Count : Natural range 0 .. 16 := 0;
      Minimum_Trust : Counter := 0;
      Complete_Inventory, Dependency_Closure_Checked, Ownership_Checked,
        Data_Migrations_Checked, Secure_Boot_Path_Checked : Boolean := False;
   end record;
   type Assessment is (Admissible, Invalid_Set, Unauthenticated_Artifact,
      Missing_Foundation, Incompatible_Cohort, Unchecked_Effects);
   function Evaluate (C : Composition) return Assessment with Global => null;
   -- Object_Digest is the original RPM hash for packaged objects, or the exact
   -- admitted derived-image hash for initramfs/recovery images. Derived images
   -- require a signed build/source binding; they are NOT fabricated RPMs.
   -- Exact immutable artifact cohort checker, NOT an RPM resolver or scriptlet
   -- executor. RPM/header inspection, signature policy and complete inventory
   -- attestations are established by the existing admission path, not a request.
   -- One selected active kernel per composition; fallback kernels are separate
   -- admitted recovery compositions. No foreign-distro packages by extension.
end Pkg_System_Composition;
