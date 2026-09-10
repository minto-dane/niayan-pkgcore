-- SPDX-License-Identifier: BSD-3-Clause
with MC_SHA256;
package body MC_Golden with SPARK_Mode is
   function Header return MC_Protocol.Header is
      Empty_Body : constant Bytes := (1..0=>0);
   begin
      return (Kind=>MC_Protocol.Inspect_Request,Request_ID=>(others=>1),
        Cluster_ID=>(others=>2),Node_ID=>(others=>3),Resource_ID=>(others=>4),
        Membership_Epoch=>1,Fence_Token=>7,Sequence_Number=>1,Deadline=>100,
        Boot_ID=>(others=>5),Body_Digest=>MC_SHA256.Hash(Empty_Body),others=><>);
   end Header;
end MC_Golden;
