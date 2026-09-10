-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Clock with SPARK_Mode => Off is
   procedure Boottime_Milliseconds (Now : out Counter; Status : out Outcome);
   procedure Realtime_Seconds (Now : out Counter; Status : out Outcome);
   procedure Read_Boot_ID (ID : out Identity; Status : out Outcome);
   -- Lease times use CLOCK_BOOTTIME, never controller wall time.
end MC_Clock;
