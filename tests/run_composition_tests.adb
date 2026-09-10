-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with Pkg_System_Composition;
with Test_Support; use Test_Support;
procedure Run_Composition_Tests with SPARK_Mode => Off is
   package P renames Pkg_System_Composition; use type P.Assessment;
   C, Bad : P.Composition;
   Roles : constant array (Positive range 1 .. 8) of P.Role :=
     (P.Kernel,P.Initramfs,P.Boot_Loader,P.Recovery_Image,P.Service_Manager,
      P.C_Library,P.Kernel_Module,P.Driver_Userspace);
begin
   C.Plan := (others => 1); C.Distribution := (others => 2); C.Snapshot := (others => 3);
   C.Count := 8; C.Publisher_Count := 1; C.Publishers (1) := (others => 4); C.Minimum_Trust := 1;
   C.Complete_Inventory := True; C.Dependency_Closure_Checked := True; C.Ownership_Checked := True;
   C.Data_Migrations_Checked := True; C.Secure_Boot_Path_Checked := True;
   for I in 1 .. 8 loop
      C.Artifacts (I) := (Object_Digest => (others => Byte (I)),Payload => (others => Byte (I+10)),
        Distribution => C.Distribution,Snapshot => C.Snapshot,Publisher => C.Publishers (1),
        ABI => (others => 6),Target_Kernel => Zero_Digest,Driver_ABI => Zero_Digest,
        Kind => Roles (I),Trust_Epoch => 1,others => True);
   end loop;
   C.Artifacts (2).Target_Kernel := C.Artifacts (1).Object_Digest;
   C.Artifacts (7).Target_Kernel := C.Artifacts (1).Object_Digest;
   C.Artifacts (7).Driver_ABI := (others => 7); C.Artifacts (8).Driver_ABI := (others => 7);
   Expect (P.Evaluate (C) = P.Admissible,"coherent-kernel-initramfs-driver-cohort");
   Bad := C; Bad.Artifacts (2).Target_Kernel := (others => 9);
   Expect (P.Evaluate (Bad) = P.Incompatible_Cohort,"initramfs-for-other-kernel-refused");
   Bad := C; Bad.Artifacts (7).ABI := (others => 9);
   Expect (P.Evaluate (Bad) = P.Incompatible_Cohort,"module-abi-mismatch");
   Bad := C; Bad.Artifacts (8).Driver_ABI := (others => 8);
   Expect (P.Evaluate (Bad) = P.Incompatible_Cohort,"driver-userspace-pair-mismatch");
   Bad := C; Bad.Artifacts (4).Kind := P.User_Package;
   Expect (P.Evaluate (Bad) = P.Missing_Foundation,"missing-recovery-image");
   Bad := C; Bad.Artifacts (2).Snapshot := (others => 9);
   Expect (P.Evaluate (Bad) = P.Unauthenticated_Artifact,"mixed-repository-snapshot");
   Bad := C; Bad.Artifacts (8).Distribution := (others => 9);
   Expect (P.Evaluate (Bad) = P.Unauthenticated_Artifact,"foreign-distribution-denied");
   Bad := C; Bad.Artifacts (5).Recovery_Pinned := False;
   Expect (P.Evaluate (Bad) = P.Unchecked_Effects,"unpinned-recovery-object");
   Bad := C; Bad.Artifacts (6).Effects_Covered := False;
   Expect (P.Evaluate (Bad) = P.Unchecked_Effects,"unknown-scriptlet-effects");
   Bad := C; Bad.Complete_Inventory := False;
   Expect (P.Evaluate (Bad) = P.Invalid_Set,"partial-inventory-never-a-distro");
   Report;
end Run_Composition_Tests;
