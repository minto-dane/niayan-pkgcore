-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Compatibility with SPARK_Mode, Pure is
   type Contract_Descriptor is record
      Major : Natural range 0 .. 65_535 := 2;
      Minor : Natural range 0 .. 65_535 := 0;
      Schema_Digest : Digest := Zero_Digest;
      Supports : Wide := 0;
      Requires_Features : Wide := 0;
      Maximum_Body : Natural range 0 .. Max_Message := Max_Message;
   end record;
   function Compatible (Local, Peer : Contract_Descriptor) return Boolean
     with Global => null;
end MC_Compatibility;
