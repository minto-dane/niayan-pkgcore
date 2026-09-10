-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Protocol;
package MC_Authorization with SPARK_Mode, Pure is
   type Kind_Set is array (MC_Protocol.Message_Kind) of Boolean;
   type Scope is record
      Cluster_ID, Node_ID, Resource_ID, Boot_ID : Identity := Zero_Identity;
      Membership_Epoch, Fence_Token : Counter := 0;
      Allowed : Kind_Set := (others => False);
      Maximum_Local_Lease : Counter := 30_000; -- milliseconds
   end record;
   function Within_Scope
     (H : MC_Protocol.Header; Policy : Scope; Now : Counter) return Boolean
     with Global => null;
   -- This predicate DOES NOT authenticate a header. Only evaluate an authenticated
   -- MC_Signatures message under an independently provisioned Scope.
   -- Deadlines must come from receiver-local boot-bound lease issuance.
end MC_Authorization;
