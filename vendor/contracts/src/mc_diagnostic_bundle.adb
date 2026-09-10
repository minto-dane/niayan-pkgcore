-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Diagnostic_Bundle with SPARK_Mode is
   function Base_OK(B:Bundle; Now:Counter) return Boolean is
     (B.Incident_ID/=Zero_Identity and then B.Node_ID/=Zero_Identity and then B.Boot_ID/=Zero_Identity
      and then B.Manifest/=Zero_Digest and then B.Policy/=Zero_Digest and then B.Captured_At>0 and then B.Captured_At<=Now
      and then B.Expires_At>Now and then B.Authenticated and then B.Redaction_Policy_Applied
      and then B.Encrypted_At_Rest and then B.Preserved_Remotely and then B.Immutable_Receipt);
   function Sufficient_For_Kernel_Incident (B : Bundle; Now : Counter) return Boolean is
     (Base_OK(B,Now) and then B.Classes(Audit) and then B.Classes(Kernel_Log)
      and then (B.Classes(Pstore) or else B.Classes(Kdump)) and then B.Classes(Hardware_RAS)
      and then B.Classes(Attestation));
   function Sufficient_For_Change_Incident (B : Bundle; Now : Counter) return Boolean is
     (Base_OK(B,Now) and then B.Classes(Audit) and then B.Classes(Package_Journal)
      and then B.Classes(Service_State) and then B.Classes(Cluster));
end MC_Diagnostic_Bundle;
