-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Diagnostic_Bundle with SPARK_Mode, Pure is
   type Evidence_Class is
     (Audit, Package_Journal, Service_State, Kernel_Log, Pstore, Kdump,
      Hardware_RAS, Storage, Network, Attestation, Cluster, Application);
   type Presence is array (Evidence_Class) of Boolean;
   type Bundle is record
      Incident_ID, Node_ID, Boot_ID : Identity := Zero_Identity;
      Manifest, Policy : Digest := Zero_Digest;
      Classes : Presence := (others=>False);
      Captured_At, Expires_At : Counter := 0;
      Authenticated, Redaction_Policy_Applied, Encrypted_At_Rest : Boolean := False;
      Preserved_Remotely, Immutable_Receipt : Boolean := False;
   end record;
   function Sufficient_For_Kernel_Incident (B : Bundle; Now : Counter) return Boolean with Global=>null;
   function Sufficient_For_Change_Incident (B : Bundle; Now : Counter) return Boolean with Global=>null;
end MC_Diagnostic_Bundle;
