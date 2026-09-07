-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Attestation with SPARK_Mode, Pure is
   type Trust is (Rejected, Restricted, Trusted);
   type Policy is record
      Cluster_ID, Node_ID : Identity := Zero_Identity;
      Policy_Digest, Allowed_Boot_Profile, Allowed_Runtime_Profile : Digest := Zero_Digest;
      Minimum_Trust_Epoch : Counter := 0;
      Maximum_Evidence_Age_Ms : Counter := 60_000;
      Require_Secure_Boot, Require_Measured_Boot, Require_TPM_Quote : Boolean := True;
      Require_IMA_Appraisal, Require_Module_Signing, Require_Lockdown : Boolean := True;
   end record;
   type Evidence is record
      Cluster_ID, Node_ID, Boot_ID : Identity := Zero_Identity;
      Policy_Digest, Boot_Profile, Runtime_Profile, Quote_Digest : Digest := Zero_Digest;
      Trust_Epoch, Sequence, Observed_At, Expires_At : Counter := 0;
      Quote_Verified, Nonce_Bound, Event_Log_Consistent : Boolean := False;
      Secure_Boot, Measured_Boot, IMA_Appraisal, Module_Signing, Lockdown : Boolean := False;
   end record;
   function Valid (P : Policy) return Boolean with Global => null;
   function Valid (E : Evidence) return Boolean with Global => null;
   function Evaluate (P : Policy; E : Evidence; Now : Counter) return Trust
     with Global => null;
   -- Cryptographic quote verification is an adapter responsibility. Evidence
   -- is accepted here only after binding quote, nonce, event log and current boot.
end MC_Attestation;
