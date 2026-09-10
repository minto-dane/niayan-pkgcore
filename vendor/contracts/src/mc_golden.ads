-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Protocol;
package MC_Golden with SPARK_Mode, Pure is
   function Header return MC_Protocol.Header with Global => null;
end MC_Golden;
