-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Commissioning with SPARK_Mode, Pure is
   type Phase is
     (Uncommissioned, Hardware_Identified, Firmware_Validated, Trust_Enrolled,
      Storage_Provisioned, Recovery_Provisioned, Baseline_Installed,
      Baseline_Verified, Cluster_Admitted, Commissioned, Quarantined);
   type Command is
     (Record_Hardware, Record_Firmware, Enroll_Trust, Provision_Storage,
      Provision_Recovery, Install_Baseline, Verify_Baseline,
      Admit_Cluster, Finish, Quarantine);
   type State is record
      Node_ID, Boot_ID : Identity := Zero_Identity;
      Hardware, Firmware, Trust_Root, Storage_Layout : Digest := Zero_Digest;
      Recovery_Image, Baseline, Policy : Digest := Zero_Digest;
      Revision, Trust_Epoch : Counter := 0;
      Current : Phase := Uncommissioned;
   end record;
   type Evidence is record
      Expected_Revision, New_Trust_Epoch : Counter := 0;
      Node_ID, Boot_ID : Identity := Zero_Identity;
      Hardware, Firmware, Trust_Root, Storage_Layout : Digest := Zero_Digest;
      Recovery_Image, Baseline, Policy : Digest := Zero_Digest;
      Secure_Boot, TPM_Owned, Firmware_Authenticated : Boolean := False;
      Disk_Encryption, Recovery_Sealed, Baseline_Signed : Boolean := False;
      Baseline_Attested, Restore_Tested, Audit_Reachable : Boolean := False;
      Cluster_Admission_Authorized, Fencing_Ready : Boolean := False;
   end record;
   procedure Step (S : in out State; C : Command; E : Evidence; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then (if Status = OK then S.Revision > S'Old.Revision);
   -- Destructive disk/firmware operations are intentionally outside this pure
   -- state machine.  An adapter must bind evidence to the exact node and policy.
end MC_Commissioning;
