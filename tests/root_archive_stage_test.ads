-- SPDX-License-Identifier: MIT
with MC_Store; with MC_Types; use MC_Types;
with Pkg_Selected_Catalog;
package Root_Archive_Stage_Test with SPARK_Mode => Off is
   procedure Run (Store : in out MC_Store.Store; Store_Path : String;
      Catalog, Closure, Root_Manifest, Archive : Digest;
      Packages : Pkg_Selected_Catalog.Selection; Deadline : Counter);
end Root_Archive_Stage_Test;
