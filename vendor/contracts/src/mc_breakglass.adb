-- SPDX-License-Identifier: MIT
package body MC_Breakglass with SPARK_Mode is
   function Permitted (R : Request; Now, Current_Trust_Epoch : Counter) return Boolean is
   begin
      if R.Request_ID=Zero_Digest or else R.Scope=Zero_Digest or else R.Reason=Zero_Digest
        or else R.Evidence=Zero_Digest or else R.Trust_Epoch=0 or else R.Trust_Epoch<Current_Trust_Epoch
        or else R.Not_Before>Now or else R.Expires_At<=Now or else R.Expires_At<=R.Not_Before
        or else not R.Operations_Approved or else not R.Security_Approved
        or else not R.Independent_Approvers or else not R.Audit_Sink_Reachable
      then return False; end if;
      return R.Requested not in Disable_Verification | Disable_Audit | Disable_Encryption;
   end Permitted;
end MC_Breakglass;
