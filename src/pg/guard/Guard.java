package pg.guard;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.xmlpull.v1.XmlPullParserException;

import soot.PackManager;
import soot.Scene;
import soot.Transform;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.util.dot.DotGraph;

public class Guard {
	static FileWriter resultFile = null;
	static FileWriter detailFile = null;
	// static FileWriter logFile = null;
	static HashMap<String, String> alternativeApi = new HashMap<String, String>();
	static HashMap<String, String> alternativeUri = new HashMap<String, String>();
	static HashMap<String, String> alternativeUriString = new HashMap<String, String>();
	static HashMap<String, String> alternativeIntents = new HashMap<String, String>();
	static ArrayList<ArrayList<String>> injectPermissionMeta = new ArrayList<>();
	static ArrayList<String> injectMethodMeta = new ArrayList<>();

	// fix me : this is not safe because a method can be invoked by more then once
	// static HashMap<SootMethod, InstrumentMeta> metas = new HashMap<>();

	static {
		try {
			resultFile = new FileWriter("result1.log");
			detailFile = new FileWriter("detail1.log");
			// logFile = new FileWriter("log.log");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private class VersionNotFitException extends Exception {
	}

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		// Logger log = LoggerFactory.getLogger(Guard.class);
		
		if (args.length != 3) {
			System.out.println("permission-guard uasge: permission-guard apk-path android-platforms iccModel");
			return;
		}
		String apkFile = args[0];
		try {
			resultFile.write(apkFile + "\n");
			detailFile.write(apkFile + "\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String androidPlatform = args[1];
		String iccModel = null;
		if (args.length == 3) {
			iccModel = args[2];
		}
		Guard guard = new Guard();

		Set<String> permissionNeeded = null;
		try {
			permissionNeeded = guard.ManifestProcessor(apkFile);
		} catch (VersionNotFitException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			//System.out.println("here");
			resultFile.write("android version is under 23!\n");
			return;
		}
		if (permissionNeeded != null && permissionNeeded.isEmpty()) {
			// logFile.write("no dangerous permissions needed!");
			return;
		} else {
			for (String permission : permissionNeeded) {
				resultFile.write(permission + "\n");
			}
		}

		guard.apiFileProcessor(permissionNeeded);
		guard.uriFileProcessor(permissionNeeded);
		guard.uriStringFileProcessor(permissionNeeded);
		guard.intentsFileProcessor(permissionNeeded);
		// System.out.println("here");

		SetupApplication app = new SetupApplication(androidPlatform, apkFile);

		if (iccModel != null && iccModel.length() > 0) {
			app.getConfig().getIccConfig().setIccModel(iccModel);
		}
		app.setSootConfig(new IInfoflowConfig() {

			@Override
			public void setSootOptions(Options options, InfoflowConfiguration config) {
				// TODO Auto-generated method stub
				Options.v().set_process_multiple_dex(true);
				Options.v().set_verbose(true);
			}
			
		});
		app.getConfig().setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		app.constructCallgraph();
//		guard.renderCFG();
		CheckHunter hunter = new CheckHunter();
		hunter.hunt();
		
//		for (String s : Guard.injectMethodMeta) {
//			System.out.println(s);
//		}

		resultFile.close();
		detailFile.close();
		soot.G.reset();
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_prepend_classpath(true);
		Options.v().set_validate(true);
		Options.v().set_android_jars(androidPlatform);
		Options.v().set_process_dir(Collections.singletonList(apkFile));
		Options.v().set_output_format(Options.output_format_dex);
		// Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_force_overwrite(true);
		Options.v().set_whole_program(true);
		Options.v().set_verbose(true);
		Options.v().set_process_multiple_dex(true);
		Scene.v().loadNecessaryClasses();
		System.out.println("start permission instrument ...");
		System.out.println("instrument meta size is " + Guard.injectMethodMeta.size());

		PackManager.v().getPack("jtp").add(new Transform("jtp.myAnalysis", new PermissionTransformer()));
		PackManager.v().runPacks();
		PackManager.v().writeOutput();
	}

	private void intentsFileProcessor(Set<String> permissionNeeded) {
		String intentsFile = "./res/dangrousIntents.txt";
		BufferedReader reader = null;
		String line = null;

		try {
			reader = new BufferedReader(new FileReader(intentsFile));
			while ((line = reader.readLine()) != null) {
				String[] array = line.split(" ");
				if (permissionNeeded.contains(array[1])) {
					alternativeIntents.put(array[0], array[1]);
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// fix me : manifest uriString process
	private void uriStringFileProcessor(Set<String> permissionNeeded) {
		String uriStringFile = "./res/dangerousUriString.txt";
		BufferedReader reader = null;
		String line = null;// , curPermission = null;
		try {
			reader = new BufferedReader(new FileReader(uriStringFile));
			while ((line = reader.readLine()) != null) {
				String[] array = line.split(" ");
				if ((array[1] == "R" || array[1] == "W") && permissionNeeded.contains(array[2])) {
					alternativeUriString.put(array[0], array[2]);
				}
				// fix me : is this
				// else if (array.length == 3 && permissionNeeded.contains(array[1])) {
				// alternativeUriString.put(array[0], array[1]);
				// }
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// uri的jimple表示有没有带类型信息？
	private void uriFileProcessor(Set<String> permissionNeeded) {
		String uriFile = "./res/dangerousUri.txt";
		BufferedReader reader = null;
		String line = null, curPermission = null;
		try {
			reader = new BufferedReader(new FileReader(uriFile));
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("PERMISSION")) {
					int colonIndex = line.indexOf(":");
					curPermission = line.substring(colonIndex + 1);
				} else if (line.startsWith("<")) {
					// int spaceIndex = line.indexOf(" ");
					// String apiCall = line.substring(0, spaceIndex);
					if (permissionNeeded.contains(curPermission)) {
						alternativeUri.put(line, curPermission);
					}
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void apiFileProcessor(Set<String> permissionNeeded) {
		String apiFile = "./res/dangerousAPI.txt";
		BufferedReader reader = null;
		String line = null, curPermission = null;
		try {
			reader = new BufferedReader(new FileReader(apiFile));
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("Permission")) {
					int colonIndex = line.indexOf(":");
					curPermission = line.substring(colonIndex + 1);
				} else if (line.startsWith("<")) {
					// int spaceIndex = line.indexOf(" ");
					// String apiCall = line.substring(0, spaceIndex);
					if (permissionNeeded.contains(curPermission)) {
						// alternativeApi.put(apiCall, curPermission);
						alternativeApi.put(line, curPermission);
					}
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// 返回空集合表明改Apk没有需要申请的权限
	private Set<String> ManifestProcessor(String apkFile) throws VersionNotFitException {
		ProcessManifest manifest = null;
		DangerousPermission dangrousPermissions = new DangerousPermission();
		int targetSdkVersion = 0;
		Set<String> permissionList = null;
		// Logger log = LoggerFactory.getLogger(Guard.class);
		try {
			manifest = new ProcessManifest(apkFile);
			permissionList = manifest.getPermissions();
			targetSdkVersion = manifest.targetSdkVersion();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XmlPullParserException e) {
			e.printStackTrace();
		}

		if (targetSdkVersion < 23) {
			throw new VersionNotFitException();
		}

		Set<String> result = new HashSet<>();

		for (String permission : permissionList) {
			if (dangrousPermissions.contains(permission)) {
				// permissionList.remove(permission);
				result.add(permission);
			}
		}
		// for (String permission : dangrousPermissions) {
		//
		// }
		if (result.isEmpty()) {
			System.out.println("this apk has no dangrous permission need to query at runtime!");
			System.out.println("permission-guard exit because no dangrous permission found!");
		}
		return result;
	}

	// private void renderICFG() {
	// InfoflowCFG icfg = new InfoflowCFG();
	// }

	private void renderCFG() {
		// System.out.println(Scene.v().getCallGraph().size() + "");
		CallGraph cg = Scene.v().getCallGraph();
		Iterator<Edge> iter = cg.iterator();
		DotGraph dotGraph = new DotGraph("defult-dotgraph");
		// HashSet<MethodOrMethodContext> nodes = new HashSet<>();
		while (iter.hasNext()) {
			Edge edge = iter.next();
			dotGraph.drawNode(edge.getSrc().method().getSignature());
			dotGraph.drawNode(edge.getTgt().method().getSignature());
			dotGraph.drawEdge(edge.getSrc().method().getSignature(), edge.getTgt().method().getSignature());
		}
		dotGraph.plot("./call-graph.dot");
	}
}
