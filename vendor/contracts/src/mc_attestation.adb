-- SPDX-License-Identifier: MIT
package body MC_Attestation with SPARK_Mode is
   function Valid (P : Policy) return Boolean is
     (P.Cluster_ID /= Zero_Identity and then P.Node_ID /= Zero_Identity
      and then P.Policy_Digest /= Zero_Digest and then P.Allowed_Boot_Profile /= Zero_Digest
      and then P.Allowed_Runtime_Profile /= Zero_Digest and then P.Minimum_Trust_Epoch > 0
      and then P.Maximum_Evidence_Age_Ms > 0);
   function Valid (E : Evidence) return Boolean is
     (E.Cluster_ID /= Zero_Identity and then E.Node_ID /= Zero_Identity
      and then E.Boot_ID /= Zero_Identity and then E.Policy_Digest /= Zero_Digest
      and then E.Boot_Profile /= Zero_Digest and then E.Runtime_Profile /= Zero_Digest
      and then E.Quote_Digest /= Zero_Digest and then E.Trust_Epoch > 0
      and then E.Sequence > 0 and then E.Observed_At > 0
      and then E.Expires_At > E.Observed_At);
   function Evaluate (P : Policy; E : Evidence; Now : Counter) return Trust is
   begin
      if not Valid (P) or else not Valid (E)
        or else E.Cluster_ID /= P.Cluster_ID or else E.Node_ID /= P.Node_ID
        or else E.Policy_Digest /= P.Policy_Digest or else E.Trust_Epoch < P.Minimum_Trust_Epoch
        or else E.Expires_At <= Now or else E.Observed_At > Now
        or else Now - E.Observed_At > P.Maximum_Evidence_Age_Ms
        or else not E.Quote_Verified or else not E.Nonce_Bound
        or else not E.Event_Log_Consistent
      then return Rejected; end if;
      if E.Boot_Profile /= P.Allowed_Boot_Profile
        or else E.Runtime_Profile /= P.Allowed_Runtime_Profile
      then return Restricted; end if;
      if (P.Require_Secure_Boot and then not E.Secure_Boot)
        or else (P.Require_Measured_Boot and then not E.Measured_Boot)
        or else (P.Require_TPM_Quote and then not E.Quote_Verified)
        or else (P.Require_IMA_Appraisal and then not E.IMA_Appraisal)
        or else (P.Require_Module_Signing and then not E.Module_Signing)
        or else (P.Require_Lockdown and then not E.Lockdown)
      then return Restricted; end if;
      return Trusted;
   end Evaluate;
end MC_Attestation;
