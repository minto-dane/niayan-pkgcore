-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Authorization with SPARK_Mode is
   function Within_Scope
     (H : MC_Protocol.Header; Policy : Scope; Now : Counter) return Boolean is
     (MC_Protocol.Valid_Identity (H)
      and then H.Cluster_ID = Policy.Cluster_ID
      and then H.Node_ID = Policy.Node_ID
      and then H.Resource_ID = Policy.Resource_ID
      and then H.Boot_ID = Policy.Boot_ID
      and then H.Membership_Epoch = Policy.Membership_Epoch
      and then H.Fence_Token = Policy.Fence_Token
      and then Policy.Allowed (H.Kind)
      and then H.Deadline > Now
      and then H.Deadline - Now <= Policy.Maximum_Local_Lease);
end MC_Authorization;
