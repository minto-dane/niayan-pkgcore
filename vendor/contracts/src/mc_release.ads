-- SPDX-License-Identifier: BSD-3-Clause
package MC_Release with SPARK_Mode, Pure is
   type Evidence_Item is
     (Compiler_Build, All_Unit_Tests, Integration_Tests, Protocol_Matrix,
      Proof_Flow, Proof_Safety, Proof_Functional, Crypto_Review,
      RPM_Corpus, Filesystem_Crash_Tests, Powercut_Tests, Cluster_Partition_Tests,
      Fence_Device_Tests, Secure_Boot_Tests, Backup_Restore_Tests,
      Supply_Chain_Review, Independent_Review, Operational_Approval,
      Control_Threshold_Tests, Nonrollback_Anchor_Tests, Backup_Chain_Tests,
      Readmission_Isolation_Tests, Disaster_Rehearsal_Tests,
      Batch_Retention_Race_Tests, Etcd_Value_Limit_Tests,
      Host_Admission_Tests, Service_Catalogue_Tests, Network_Recovery_Tests,
      Boot_Trial_Tests, Distribution_Composition_Tests, Native_RPM_Integration_Tests);
   type Evidence_State is (Missing, Failed, Passed);
   type Evidence_Set is array (Evidence_Item) of Evidence_State;
   function Qualified (Evidence : Evidence_Set) return Boolean
     with Global => null,
       Post => Qualified'Result = (for all E of Evidence => E = Passed);
   -- This is a policy predicate, NOT a signature verifier for evidence.
   -- Release evidence must also be authenticated and tied to exact artifact hashes.
   Build_Qualified : constant Boolean := False;
end MC_Release;
