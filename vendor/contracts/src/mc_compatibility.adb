-- SPDX-License-Identifier: MIT
package body MC_Compatibility with SPARK_Mode is
   use type Wide;
   function Compatible (Local, Peer : Contract_Descriptor) return Boolean is
     (Local.Major = Peer.Major and then Local.Minor = Peer.Minor
      and then not Is_Zero (Local.Schema_Digest)
      and then Same_Bytes (Local.Schema_Digest, Peer.Schema_Digest)
      and then (Local.Requires_Features and not Peer.Supports) = 0
      and then (Peer.Requires_Features and not Local.Supports) = 0
      and then Local.Maximum_Body > 0 and then Peer.Maximum_Body > 0);
end MC_Compatibility;
