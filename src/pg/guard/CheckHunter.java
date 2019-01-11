package pg.guard;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import soot.Body;
import soot.BodyTransformer;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.JimpleBody;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.util.Chain;

public class CheckHunter {
	
	public void hunt() {
		Chain<SootClass> clazzChain = Scene.v().getClasses();
		Set<SootClass> allClass = new HashSet<>();
		allClass.addAll(clazzChain);

		for (SootClass clazz : allClass) {
			if (clazz.getPackageName().startsWith("android."))
				continue;
			if (clazz.getPackageName().startsWith("java."))
				continue;
			if (clazz.getPackageName().startsWith("javax."))
				continue;
			if (clazz.getPackageName().startsWith("org.xml"))
				continue;

			List<SootMethod> methods = clazz.getMethods();
			for (int i = 0; i < methods.size(); ++i) {
				SootMethod method = methods.get(i);
//				System.out.println("analysising " + method.getSignature());
				if (method.isConcrete() && method.hasActiveBody()) {
					Body body = method.getActiveBody();
					Iterator<Unit> iter = body.getUnits().snapshotIterator();
					while (iter.hasNext()) {
						Unit unit = iter.next();
						unit.apply(new huntCheckSwitch(method));
					}
				}
			}
		}
	}
}

class huntCheckSwitch extends AbstractStmtSwitch {

	private SootMethod method;
	public huntCheckSwitch(SootMethod method) {
		// this.unit = unit;
		this.method = method;
//		System.out.println(method.getSignature());
	}

	@Override
	public void caseIfStmt(IfStmt stmt) {
		if (stmt.containsInvokeExpr()) {
			huntApi(this.method, stmt);
			huntIntents(this.method, stmt);
		}
	}

	@Override
	public void caseAssignStmt(AssignStmt stmt) {
		super.caseAssignStmt(stmt);
		huntUri(this.method, stmt);
		if (stmt.containsInvokeExpr()) {
			huntApi(this.method, stmt);
			huntIntents(this.method, stmt);
		}
	}

	@Override
	public void caseInvokeStmt(InvokeStmt stmt) {
		super.caseInvokeStmt(stmt);
		huntApi(this.method, stmt);
		huntIntents(this.method, stmt);
	}

	private boolean hasCheckInMethod(SootMethod curMethod, String permission) {
		Deque<SootMethod> queue = new LinkedList<>();
		Set<SootMethod> set = new HashSet<>();
		set.add(curMethod);
		queue.addLast(curMethod);
		while (queue.isEmpty() == false) {
			SootMethod method = queue.removeFirst();
			if (method.getName().equals("checkSelfPermission")) {
//				try {
//					Guard.detailFile.write("found a check in " + method.getSignature());
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
				return true;
			}
			if (method.hasActiveBody() == false) {
				continue;
			}
			Body body = method.retrieveActiveBody();
			Iterator<Unit> iter = body.getUnits().snapshotIterator();
			while (iter.hasNext()) {
				
				Stmt stmt = (Stmt)iter.next();
				if (stmt.containsInvokeExpr() == false) {
					continue;
				}
				SootMethod callee = stmt.getInvokeExpr().getMethod();
				if (set.contains(callee) == false) {
					set.add(callee);
					queue.addLast(callee);
				}
			}
		}
		return false;
	}

	private void printPath(List<String> path) {
		try {
			if (path.size() == 1) {
				Guard.detailFile.write(path.get(0) + "has no caller\n\n");
				return ;
			}
			for (int i = path.size() - 1; i >= 0; --i) {
				Guard.detailFile.write(path.get(i) + (i == 0 ? "\n\n" : "\n==>"));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private boolean hasCheckOnCallPath(SootMethod curMethod, String permission) {
		List<String> path = new ArrayList<>();
		Set<SootMethod> visited = new HashSet<>();
		return hasCheckOnCallPath(curMethod, permission, path, visited);
	}
	
	
	private boolean hasCheckOnCallPath(SootMethod curMethod, String permission, List<String> path, Set<SootMethod> visited) {
//		System.out.println(curMethod.getSignature());
		visited.add(curMethod);
		path.add(curMethod.getSignature());
		if (curMethod.getSignature().equals("<dummyMainClass: void dummyMainMethod(java.lang.String[])>")) {
			printPath(path);
			path.remove(path.size() - 1);
			return false;
		}
		
		if (curMethod.getName().equals("onRequestPermissionsResult")) {
			printPath(path);
			path.remove(path.size() - 1);
			return true;
		}
		
		if (hasCheckInMethod(curMethod, permission)) {
			printPath(path);
			path.remove(path.size() - 1);
			return true;
		}
		
		CallGraph cg = Scene.v().getCallGraph();
		if (cg.edgesInto(curMethod).hasNext() == false) {
			printPath(path);
			path.remove(path.size() - 1);
			return false;
		}
		Iterator<Edge> iter = cg.edgesInto(curMethod);
		while (iter.hasNext()) {
			Edge edge = iter.next();
			SootMethod caller = edge.src();
			if (visited.contains(caller)) continue;
			if (hasCheckOnCallPath(caller, permission, path, visited) == true) {
				path.remove(path.size() - 1);
				return true;
			}
		}
		path.remove(path.size() - 1);
		return false;
	}

	private void findInjectMeta(SootMethod curMethod, String permission) {
		Set<SootMethod> visited = new HashSet<>();
		findInjectMeta(curMethod, permission, visited);
	}
	
	private boolean isActivity(SootClass c) {
		SootClass sc = c;
		while (sc.hasSuperclass()) {
			if (sc.getName().equals("android.app.Activity")) {
				return true;
			}
			sc = sc.getSuperclass();
		}
		return false;
	}
	
	private void findInjectMeta(SootMethod curMethod, String permission, Set<SootMethod> visited) {
//		final String activityType = "android.support.v4.app.ActivityCompat";
		CallGraph cg = Scene.v().getCallGraph();
		Iterator<Edge> iter = cg.edgesInto(curMethod);
		visited.add(curMethod);
		while (iter.hasNext()) {
//			System.out.println("has a caller");
			SootMethod caller = iter.next().src();
			SootClass callerClass = caller.getDeclaringClass();
			if (isActivity(callerClass) == true) {
//				System.out.println(curMethod.getSignature());
				int index = Guard.injectMethodMeta.indexOf(curMethod.getSignature());
				if (index == -1) {
					ArrayList<String> permissions = new ArrayList<>();
					permissions.add(permission);
					Guard.injectMethodMeta.add(curMethod.getSignature());
					Guard.injectPermissionMeta.add(permissions);
				} else if (Guard.injectPermissionMeta.get(index).contains(permission) == false){
					Guard.injectPermissionMeta.get(index).add(permission);
				}
			}
			// else we look up a level to find a component class;
			else {
				if (visited.contains(caller) == false) {
					findInjectMeta(caller, permission, visited);
				}
			}
		}
//		visited.remove(curMethod);
	}


	private void logCheckInfo(String method, String checkOrNot, String permission) {
		try {
			Guard.resultFile.write(method + ":" + checkOrNot + ":" + permission + "\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void huntApi(SootMethod curMethod, Stmt stmt) {
		if (Guard.alternativeApi.isEmpty() == true)
			return;

		SootMethod suspiciousMethod = null;
		String permission = null;
		suspiciousMethod = stmt.getInvokeExpr().getMethod();
		if (Guard.alternativeApi.containsKey(suspiciousMethod.getSignature())) {
			permission = Guard.alternativeApi.get(suspiciousMethod.getSignature());
		} else {
			return;
		}

		if (hasCheckOnCallPath(curMethod, permission) == true) {
			logCheckInfo(curMethod.getSignature(), "checked", permission);
			return;
		}
		logCheckInfo(curMethod.getSignature(), "unchecked", permission);

		findInjectMeta(suspiciousMethod, permission);

	}

	// handle uri and uri string
	// can only occur at assign statement
	// fix me : can we improve accuracy
	private void huntUri(SootMethod curMethod, AssignStmt stmt) {
		if (Guard.alternativeUriString.isEmpty())
			return;

		if (stmt.containsInvokeExpr()) {
			InvokeExpr invokeExpr = stmt.getInvokeExpr();
			if (invokeExpr.getMethod().getName().equals("parse")
					&& stmt.getLeftOp().getType().toString().equals("android.net.Uri")) {
				String uri = invokeExpr.getArg(0).toString();
				if (Guard.alternativeUriString.containsKey(uri)) {
					String permission = Guard.alternativeUriString.get(uri);

					if (hasCheckOnCallPath(curMethod, permission) == true) {
						logCheckInfo(curMethod.getSignature(), "checked", permission);
						return;
					}
					logCheckInfo(curMethod.getSignature(), "unchecked", permission);
					findInjectMeta(curMethod, permission);
				}
			}
		} else {
			if (stmt.getLeftOp().getType().toString().equals("android.net.Uri")) {
				if (Guard.alternativeUri.containsKey(stmt.getRightOp().toString())) {
					String permission = Guard.alternativeUri.get(stmt.getRightOp().toString());
					if (hasCheckOnCallPath(curMethod, permission) == true) {
						logCheckInfo(curMethod.getSignature(), "checked", permission);
						return;
					}
					logCheckInfo(curMethod.getSignature(), "unchecked", permission);
					findInjectMeta(curMethod, permission);
				}
			}
		}
	}

	// a intent action assigin can happen whether on assign statement
	// or invokeStatement
	private void huntIntents(SootMethod curMethod, Stmt stmt) {

		if (Guard.alternativeIntents.isEmpty() == true)
			return;

		if (stmt.getInvokeExpr().getMethod().getDeclaringClass().getName().equals("android.content.Intent")
				&& stmt.getInvokeExpr().getMethod().getName().equals("<init>")
				&& stmt.getInvokeExpr().getArgCount() > 0
				&& stmt.getInvokeExpr().getArg(0).getType().toString().equals("java.lang.String")) {
			String action = stmt.getInvokeExpr().getArg(0).toString();
			action = action.substring(1, action.length() - 1);
			if (Guard.alternativeIntents.containsKey(action)) {
				String permission = Guard.alternativeIntents.get(action);
				if (hasCheckOnCallPath(curMethod, permission) == true) {
					logCheckInfo(curMethod.getSignature(), "checked", permission);
					return;
				}
				logCheckInfo(curMethod.getSignature(), "unchecked", permission);
				findInjectMeta(curMethod, permission);
			}
		}
		// fix me : maybe a user defined method also called setAction
		else if (stmt.getInvokeExpr().getMethod().getName().equals("setAction")) {
			String action = stmt.getInvokeExpr().getArg(0).toString();
			if (Guard.alternativeIntents.containsKey(action)) {
				String permission = Guard.alternativeIntents.get(action);
				if (hasCheckOnCallPath(curMethod, permission) == true) {
					logCheckInfo(curMethod.getSignature(), "checked", permission);
					return;
				}
				logCheckInfo(curMethod.getSignature(), "unchecked", permission);
				findInjectMeta(curMethod, permission);
			}
		}

	}
}
