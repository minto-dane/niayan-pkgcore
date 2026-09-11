-- SPDX-License-Identifier: BSD-3-Clause
with MC_Store; with MC_Types; use MC_Types;
with Pkg_Selected_Catalog;
package Root_Archive_Stage_Test with SPARK_Mode => Off is
   procedure Run (Store : in out MC_Store.Store; Store_Path : String;
      Catalog, Closure, Root_Manifest, Archive : Digest;
      Packages : Pkg_Selected_Catalog.Selection; Deadline : Counter;
      Source_FD : Integer := -1; Prior, Incoming : Digest := Zero_Digest);
end Root_Archive_Stage_Test;
