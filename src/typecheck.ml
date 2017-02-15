open Pos
open Err
open Ast
open Env
open Tast

let is_int = function
  | Int _ -> true
  | UInt _ -> true
  | _ -> false

let is_unsigned = function
  | UInt _ -> true
  | _ -> false

let is_bool = function
  | Bool -> true
  | _ -> false

let fit_num n =
  let rec numbits = function
    | 0  -> 1
    | 1  -> 1
    | -1 -> 2
    | n  -> 1 + (numbits (n / 2))
  in
    if n < 0 then Int (numbits n)
    else UInt (numbits n)

let unify_ty t1 t2 =
  match (t1,t2) with
    | _ when equal_ctype t1 t2 -> t1
    | (Int a, Int b) -> Int (max a b)
    | (UInt a, UInt b) -> UInt (max a b)
    | (Int a, UInt b) -> Int (max a (2 * b))
    | (UInt a, Int b) -> Int (max (2 * a) b)
    | _ -> raise (TypeError((ty_to_string t1) ^
                            " does not unify with " ^
                            (ty_to_string t2)))

let unify_sz t1 t2 =
  match (t1,t2) with
    | _ when equal_ctype t1 t2 -> t1
    | (Int a, Int b) -> Int (max a b)
    | (UInt a, UInt b) -> UInt (max a b)
    | (Int a, UInt b) -> Int (max a b)
    | (UInt a, Int b) -> Int (max a b)
    | _ -> raise (TypeError((ty_to_string t1) ^
                            " does not unify with " ^
                            (ty_to_string t2)))

let unify_label lbl1 lbl2 =
  match lbl1,lbl2 with
    | Secret,_ -> Secret
    | _,Secret -> Secret
    | Public,Public -> Public
    | _ -> Unknown

let tc_unop { pos=p; data=op } ty =
  match op with
    | Neg when is_int ty -> ty
    | L_Not when is_bool ty -> ty
    | B_Not when is_int ty -> ty
    | _ -> raise @@ errTypeError p

let tc_binop { pos=p; data=op } lhs rhs =
  match op with
    | Plus when is_int(lhs) && is_int(rhs) -> unify_ty lhs rhs
    | Minus when is_int(lhs) && is_int(rhs) -> unify_ty lhs rhs
    | Multiply when is_int(lhs) && is_int(rhs) -> unify_ty lhs rhs
    | Equal when is_int(lhs) && is_int(rhs) -> Bool
    | NEqual when is_int(lhs) && is_int(rhs) -> Bool
    | GT when is_int(lhs) && is_int(rhs) -> Bool
    | GTE when is_int(lhs) && is_int(rhs) -> Bool
    | LT when is_int(lhs) && is_int(rhs) -> Bool
    | LTE when is_int(lhs) && is_int(rhs) -> Bool
    | L_And when is_bool(lhs) && is_bool(rhs) -> Bool
    | L_Or when is_bool(lhs) && is_bool(rhs) -> Bool
    | B_And when is_int(lhs) && is_int(rhs) -> unify_sz lhs rhs
    | B_Or when is_int(lhs) && is_int(rhs) -> unify_sz lhs rhs
    | B_Xor when is_int(lhs) && is_int(rhs) -> unify_sz lhs rhs
    | LeftShift when is_int(lhs) && is_unsigned(rhs) -> lhs
    | RightShift when is_int(lhs) && is_unsigned(rhs) -> lhs
    | _ -> raise @@ errTypeError p

let ty_can_flow p lhs rhs =
  match lhs, rhs with
    | a, b when equal_ctype a b -> ()
    | Int a, Int b when a > b -> ()
    | UInt a, UInt b when a > b -> ()
    | Int a, UInt b when a > (2 * b) -> ()
    | _ -> raise @@ errPassError p

let ty_can_pass p lhs rhs =
  match lhs.kind with
    | Val -> ignore(ty_can_flow p lhs.ty rhs.ty)
    | Ref
    | Arr _ ->
      if not (equal_ctype lhs.ty rhs.ty)
      then raise @@ errPassErrorS p (show_ctype lhs.ty) (show_ctype rhs.ty)

let update_public venv p v =
  let lt = get_var venv v in
    if lt.label = Unknown then update_label venv v Public

let rec fill_arg venv { pos=p; data=targ } =
  match targ with
    | TValArg texpr -> fill_public venv texpr
    | TRefArg(name,_)
    | TArrArg(name,_,_) -> update_public venv p name

and fill_public venv { pos=p; data=te } =
  match te.e with
    | TVarExp v -> update_public venv p v
    | TArrExp(v,_) -> update_public venv p v
    | TUnOp(_,e1) -> fill_public venv e1
    | TBinOp(_,e1,e2) ->
      fill_public venv e1;
      fill_public venv e2
    | TPrimitive _ -> ()
    | TCallExp(_,targs) ->
      ignore(List.map (fill_arg venv) targs)

let lbl_can_flow venv lbl ({ pos=p; data=te } as pte) =
  match lbl, te.e_lbl with
    | Public, Secret -> raise @@ errFlowError p
    | Public, Unknown -> fill_public venv pte; lbl
    | Unknown, Secret -> Secret
    | _ -> lbl

let lbl_can_pass venv lhs ({ pos=p; data=targ } as ptarg) =
  let rhs =
    match targ with
      | TValArg te -> { ty=te.data.e_ty; label=te.data.e_lbl; kind=Val }
      | TRefArg(name,vt) -> ltk vt Ref
      | TArrArg(name,vt,sz) -> ltk vt (Arr sz)
  in
  match lhs, rhs with
    | { label=Public }, { label=Secret } -> raise @@ errPassError p
    | { kind=Ref; label=Secret }, { kind=Ref; label=Public } ->
      raise @@ errPassError p
    | { label=Unknown }, { label=Secret } -> { lhs with label=Secret }
    | { label=Public }, { label=Unknown } -> fill_arg venv ptarg; lhs
    | { label=Secret }, _ -> lhs
    | _ -> lhs

let can_flow venv vt ({ pos=p; data=texpr } as ptexpr) =
  ty_can_flow p vt.v_ty texpr.e_ty;
  let lbl' = lbl_can_flow venv vt.v_lbl ptexpr in
    { vt with v_lbl=lbl' }

let kind_can_pass p lhs rhs =
  if not (equal_kind lhs rhs) then raise @@ errPassError p

let can_pass venv lhs ({ pos=p; data=targ } as ptarg) =
  ignore(
    match targ with
      | TValArg te ->
        kind_can_pass p lhs.kind Val;
        ty_can_flow p lhs.ty te.data.e_ty
      | TRefArg(name,vt) ->
        let rhs = ltk vt Ref in
          kind_can_pass p lhs.kind rhs.kind;
          ty_can_pass p lhs rhs
      | TArrArg(name,vt,sz) ->
        let rhs = ltk vt (Arr sz) in
          kind_can_pass p lhs.kind rhs.kind;
          ty_can_pass p lhs rhs);
  lbl_can_pass venv lhs ptarg

let tc_module (CModule fdecs) =
  let fenv = Env.new_fenv() in

  let rec tc_prim venv { pos=p; data=expr } =
    let make_texpr prim ty lbl =
      { e=TPrimitive (make_ast p prim); e_ty=ty; e_lbl=lbl } in
    match expr with
      | Number n -> make_texpr (TNumber n) (fit_num n) Public
      | Boolean b -> make_texpr (TBoolean b) Bool Public

  and tc_arg venv { pos=p; data=arg } =
    let tc_arg' = function
      | ValArg e ->
        let e' = tc_expr venv e in
          TValArg e'
      | RefArg(name) ->
        let lt = get_var venv name in
          TRefArg(name, vtk lt)
      | ArrArg(name) ->
        let lt = get_var venv name in
          (match lt.kind with
            | Arr sz -> TArrArg(name, vtk lt, sz)
            | _ -> raise (UnclassifiedError("not an array")))
    in make_ast p @@ tc_arg' arg

  and tc_expr venv { pos=p; data=expr } =
    let tc_expr' = function
      | VarExp v ->
        let lt = get_var venv v in
          { e=TVarExp v; e_ty=lt.ty; e_lbl=lt.label }
      | ArrExp(v,i) ->
        let i' = tc_expr venv i in
        ignore(lbl_can_flow venv Public i');
        if not (is_unsigned i'.data.e_ty) then raise @@ err p;
        (* TODO add dynamic bounds check *)
        let lt = get_arr venv v in
          { e=TArrExp(v,i'); e_ty=lt.ty; e_lbl=lt.label }
      | UnOp(op,e1) ->
        let e1' = tc_expr venv e1 in
        let ty' = tc_unop op e1'.data.e_ty in
          { e=TUnOp(op,e1'); e_ty=ty'; e_lbl=e1'.data.e_lbl }
      | BinOp(op,e1,e2) ->
        let e1' = tc_expr venv e1 in
        let e2' = tc_expr venv e2 in
        let ty' = tc_binop op e1'.data.e_ty e2'.data.e_ty in
        let lbl' = unify_label e1'.data.e_lbl e2'.data.e_lbl in
          { e=TBinOp(op,e1',e2'); e_ty=ty'; e_lbl=lbl' }
      | Primitive prim -> tc_prim venv prim
      | CallExp(name,args) ->
        let args' = List.map (tc_arg venv) args in
        let f = get_fn fenv name in
        (* TODO infer fn param labels *)
        let args_lty = List.map2 (can_pass venv) f.f_args args' in
          { e=TCallExp(name,args'); e_ty=f.f_rvt.v_ty; e_lbl=f.f_rvt.v_lbl }
    in make_ast p @@ tc_expr' expr
  in


  let rec tc_stm venv fn_vt lbl_ctx { pos=p; data=stm } =
    let unify_ctx' e = { e with e_lbl=(unify_label lbl_ctx e.e_lbl) } in
    let unify_ctx = posmap unify_ctx' in
    match stm with
    | VarDec(name,vt,expr) ->
      let expr' = unify_ctx (tc_expr venv expr) in
      let vt' = can_flow venv vt expr' in
        (* XXX need to check if redefining variable *)
        add_var venv name (ltk vt' Val);
        TVarDec(name,vt',expr'), Public
    | ArrDec(name,vt,size,init) ->
      if not (is_int vt.v_ty) then raise @@ err p;
      add_var venv name (ltk vt (Arr size));
      TArrDec(name,vt,size,init), Public
    | Assign(name,expr) ->
      let expr' = unify_ctx (tc_expr venv expr) in
      let lt = get_var venv name in
        let vt' = can_flow venv (vtk lt) expr' in
          update_label venv name vt'.v_lbl;
          TAssign(name,expr'), Public
    | ArrAssign(name,i,expr) ->
      let i' = tc_expr venv i in
      if not (is_unsigned i'.data.e_ty) then raise @@ err p;
      (* TODO add dynamic bounds check *)
      let expr' = unify_ctx (tc_expr venv expr) in
      let lt = get_arr venv name in
      let vt = can_flow venv (vtk lt) expr' in
        update_label venv name vt.v_lbl;
        TArrAssign(name,i',expr'), Public
    | If(cond,tstms,fstms) ->
      let cond' = tc_expr venv cond in
      if not (is_bool cond'.data.e_ty) then raise @@ err p;
      let lbl_ctx' = unify_label lbl_ctx cond'.data.e_lbl in
      let tstms',ctx_t = tc_block (Env.sub_env venv) fn_vt lbl_ctx' tstms in
      let fstms',ctx_f = tc_block (Env.sub_env venv) fn_vt lbl_ctx' fstms in
        TIf(cond',tstms',fstms'), (unify_label ctx_t ctx_f)
    | For(name,ty,l,h,body) ->
      if not (is_int ty) then raise @@ err p;
      let l' = tc_expr venv l in
      let h' = tc_expr venv h in
      let vt = { v_ty=ty; v_lbl=Public } in
      ignore(can_flow venv vt l');
      ignore(can_flow venv vt h');
      let venv' = Env.sub_env venv in
        add_var venv' name { ty=ty; label=Public; kind=Val };
        let body',_ = tc_block venv' fn_vt lbl_ctx body in
          TFor(name,ty,l',h',body'), Public
    | Return expr ->
      let expr' = unify_ctx (tc_expr venv expr) in
      let fn_vt' = can_flow venv fn_vt expr' in
        TReturn expr', lbl_ctx

  and tc_block venv fn_vt lbl_ctx stms =
    let stms',lbl = tc_stms venv fn_vt lbl_ctx stms in
      { venv=venv; body=stms' }, lbl

  and tc_stms venv fn_vt lbl_ctx = function
    | [] -> [], lbl_ctx
    | stm::stms ->
      let stm',lbl_ctx' = tc_stm venv fn_vt lbl_ctx stm in
      let stm' = { pos=stm.pos; data=stm' } in
      let lbl_ctx' = unify_label lbl_ctx lbl_ctx' in
      let stms',_ = tc_stms venv fn_vt lbl_ctx' stms in
        stm'::stms', lbl_ctx'
  in

  let rec set_missing_labels_to_public block =
    let rec fill_stms { venv; body=stms } =
      let fill_stm { data=stm } =
        match stm with
          | TIf(e,s1,s2) ->
            fill_stms s1;
            fill_stms s2
          | TFor(_,_,l,h,s) ->
            fill_stms s
          | _ -> ()
      in
        ignore(List.map fill_stm stms);
        Env.fill_vtbl_public venv

    and tc_tblock ({ venv; body=stms } as block) =
      let rec tc_texpr { pos=p; data=texpr } =
        let tc_texpr' = function
          | TVarExp v ->
            let lt = get_var venv v in
              { texpr with e_lbl=lt.label }
          | TArrExp(v,i) ->
            let i' = tc_texpr i in
            let lt = get_arr venv v in
              { texpr with e=TArrExp(v,i'); e_lbl=lt.label }
          | TUnOp(op,e1) ->
            let e1' = tc_texpr e1 in
              { texpr with e=TUnOp(op,e1'); e_lbl=e1'.data.e_lbl }
          | TBinOp(op,e1,e2) ->
            let e1' = tc_texpr e1 in
            let e2' = tc_texpr e2 in
            let lbl' = unify_label e1'.data.e_lbl e2'.data.e_lbl in
              { texpr with e=TBinOp(op,e1',e2'); e_lbl=lbl' }
          | TPrimitive prim -> texpr
          | TCallExp(name,args) ->
            let args' = List.map tc_targ args in
            let f = get_fn fenv name in
              { texpr with e=TCallExp(name,args'); e_lbl=f.f_rvt.v_lbl }
        in make_ast p @@ tc_texpr' texpr.e
      and tc_targ { pos=p; data=arg } =
        let tc_targ' = function
          | TValArg e -> TValArg(tc_texpr e)
          | TRefArg(n,vt) -> TRefArg(n,vtk @@ get_var venv n)
          | TArrArg(n,vt,sz) -> TArrArg(n,vtk @@ get_var venv n,sz)
        in make_ast p @@ tc_targ' arg
      and tc_tstms stms =
        List.map
          (fun { pos=p; data=stm } ->
             let stm' =
               begin
                 match stm with
                   | TVarDec(v,vt,e) ->
                     TVarDec(v,vtk (get_var venv v),tc_texpr e)
                   | TArrDec (v,vt,s,init) ->
                     TArrDec(v,vtk (get_var venv v),s,init)
                   | TAssign(v,e) ->
                     TAssign(v,tc_texpr e)
                   | TArrAssign(v,i,e) ->
                     TArrAssign(v,tc_texpr i,tc_texpr e)
                   | TIf(e,bt,bf) ->
                     TIf(tc_texpr e,tc_tblock bt,tc_tblock bf)
                   | TFor(v,vt,l,h,b) ->
                     TFor(v,vt,tc_texpr l,tc_texpr h,tc_tblock b)
                   | TReturn e ->
                     TReturn(tc_texpr e)
               end
             in make_ast p @@ stm')
          stms
      in { block with body=tc_tstms stms }
    in
      fill_stms block;
      tc_tblock block
  in

  let tc_param venv { pos=p; data=arg } =
    let { name=n; lt } = arg in
    (* XXX eventually we will have proper label inference for parameters
       * but for now we just assume public *)
    let lt' = if lt.label = Unknown then { lt with label=Public } else lt in
      add_var venv n lt';
      { pos=p; data={ arg with lt=lt' } }
  in

  let tc_fdec { pos=p; data=fdec } =
    let venv = new_env() in
    let params' = List.map (tc_param venv) fdec.params in
    (* XXX eventually we will have proper label inference for functions
       * but for now we just assume secret *)
    let rvt' = if fdec.rvt.v_lbl = Unknown
      then { fdec.rvt with v_lbl=Secret } else fdec.rvt in
    let body',_ = tc_block venv rvt' Public fdec.body in
    let body' = set_missing_labels_to_public body' in
    let fdec' = { t_name=fdec.name; t_params=params';
                  t_rvt=rvt'; t_body=body' } in
    let fdec' = { pos=p; data=fdec' } in
      Tast.update_fn fenv fdec'; fdec'
  in
    TCModule(fenv, List.map tc_fdec fdecs)
