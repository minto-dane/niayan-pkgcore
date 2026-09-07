-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Runtime with SPARK_Mode => Off is
   procedure Initialize(Status : out Outcome);
end MC_Runtime;
