-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Text;
package MC_Layout with SPARK_Mode => Off is
   type Layout is record Root, State, Store, Ledger, Spool, Binding : MC_Text.Value; end record;
   procedure Load(Policy_Directory : String; For_Packages : Boolean; L : out Layout; Status : out Outcome);
   -- Protected administrator paths.conf; paths never come from network requests.
end MC_Layout;
