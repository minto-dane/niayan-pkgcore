-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with Pkg_File_Engine;
with Resolver_Model; with Resolver_Admission;
generic
   with procedure Authorize (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Observe (Root_ID, Transaction_ID : Identity; Plan : Digest;
      Phase : String; U : out Resolver_Model.Universe; Proposal : out Resolver_Model.Proposal;
      A : out Resolver_Admission.Admission; Expected : out Resolver_Model.Binding;
      Expected_Universe, Native_Source, Reservation : out Digest;
      Now, Trust_Floor : out Counter; Status : out Outcome);
   with procedure Check_Native (U : Resolver_Model.Universe; Proposal : Resolver_Model.Proposal;
      Native_Source, Physical_Plan, Reservation : Digest; Phase : String; Status : out Outcome);
   with procedure Recheck_Current (Expected : Resolver_Model.Binding;
      Universe_Hash, Native_Source, Physical_Plan, Reservation : Digest;
      Expires, Trust_Floor : Counter; Status : out Outcome);
package Pkg_Resolution_Engine with SPARK_Mode => Off is
   procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   package Engine is new Pkg_File_Engine (Guard);
   -- Opt-in integration, no permissive default callbacks.
   -- Authorize must include original authority, stop barrier AND configuration
   -- gate. Observe must authenticate and freeze source/inventory under the same
   -- writer reservation. Check_Native reinterprets ORIGINAL native metadata and
   -- binds all file/script/trigger effects to the exact physical plan, including
   -- effects of already-installed packages. A typed record is not attestation.
   -- In particular native validation binds U.Subject.Generation to the exact
   -- source catalog/image and physical plan direction; it is not the cluster's
   -- membership Epoch or Fence. Those are checked by the original live authority.
   -- Recheck_Current must verify current authenticated observations, the still
   -- held reservation and unexpired monotonic/wall-clock policy after the
   -- potentially long checker run; it must not merely echo the expected record.
   -- A restore uses a newly admitted reverse plan; an old success is not reusable.
   -- All SDK entry points still require deployment connection and real IO tests.
end Pkg_Resolution_Engine;
