-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Stop_Barrier; with MC_Config_Receipt; with MC_Config_Auth;
with Resolver_Model; with Resolver_Admission; with Pkg_File_Engine;
generic
   with procedure Authorize (Root_ID,Transaction_ID : Identity; Plan,Evidence : Digest;
      Epoch,Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Observe_Barrier (Root_ID,Transaction_ID : Identity; Plan : Digest;
      P : out MC_Stop_Barrier.Policy; S : out MC_Stop_Barrier.State;
      Now : out Counter; Receiver_Boot : out Identity; Status : out Outcome);
   with function Required_Scope (Phase : String) return MC_Config_Receipt.Phase;
   with procedure Observe_Configuration (Root_ID,Transaction_ID : Identity; Plan : Digest; Phase : String;
      Expected : out MC_Config_Receipt.Subject; A : out MC_Config_Auth.Authority;
      C : out MC_Config_Auth.Certificate; Now,Floor : out Counter; Status : out Outcome);
   with procedure Observe_Resolution (Root_ID,Transaction_ID : Identity; Plan : Digest; Phase : String;
      U : out Resolver_Model.Universe; Proposal : out Resolver_Model.Proposal;
      A : out Resolver_Admission.Admission; Expected : out Resolver_Model.Binding;
      Expected_Universe,Native_Source,Reservation : out Digest;
      Now,Trust_Floor : out Counter; Status : out Outcome);
   with procedure Check_Native (U : Resolver_Model.Universe; Proposal : Resolver_Model.Proposal;
      Native_Source,Physical_Plan,Reservation : Digest; Phase : String; Status : out Outcome);
   with procedure Recheck_Current (Expected : Resolver_Model.Binding;
      Universe_Hash,Native_Source,Physical_Plan,Reservation : Digest;
      Expires,Trust_Floor : Counter; Status : out Outcome);
package Pkg_Managed_Engine with SPARK_Mode => Off is
   procedure Guard (Root_ID,Transaction_ID : Identity; Plan,Evidence : Digest;
      Epoch,Fence : Counter; Phase : String; Status : out Outcome);
   package Engine is new Pkg_File_Engine(Guard);
   -- All gates are mandatory generic arguments; there are no allow-all defaults.
   -- Internal component instances are body-local and cannot expose a weaker
   -- Engine through this package. Both before and after solving, the complete
   -- configuration + barrier + original live authority are rechecked.
   -- The source/native adapters must be independently authenticated, carry full
   -- input/effect closure and retain the SAME exclusive writer reservation.
   -- This is a composed execution SDK, not a provided production site adapter.
   -- Existing pkg_worker is not silently promoted or rewired without adapters.
end Pkg_Managed_Engine;
