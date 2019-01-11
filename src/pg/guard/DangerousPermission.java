package pg.guard;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DangerousPermission {
	//permission group
	private List<String> calendar = new ArrayList<String>();
	private List<String> camera = new ArrayList<String>();
	private List<String> contacts = new ArrayList<String>();
	private List<String> location = new ArrayList<String>();
	private List<String> audio = new ArrayList<String>();
	private List<String> phone = new ArrayList<String>();
	private List<String> bodySensor = new ArrayList<String>();
	private List<String> sms = new ArrayList<String>();
	private List<String> storage = new ArrayList<String>();
	private List<List<String>> permissions = new ArrayList<>();
	private Map<String, List<String>> map = new HashMap<>();
	
	public DangerousPermission() {
		calendar.add("android.permission.READ_CALENDAR");
		calendar.add("android.permission.WRITE_CALENDAR");
		permissions.add(calendar);
		
		camera.add("android.permission.CAMERA");
		permissions.add(camera);
		
		contacts.add("android.permission.READ_CONTACTS");
		contacts.add("android.permission.WRITE_CONTACTS");
		contacts.add("android.permission.GET_ACCOUNTS");
		permissions.add(contacts);
		
		location.add("android.permission.ACCESS_FINE_LOCATION");
		location.add("android.permission.ACCESS_COARSE_LOCATION");
		permissions.add(location);
		
		audio.add("android.permission.RECORD_AUDIO");
		permissions.add(audio);
		
		phone.add("android.permission.READ_PHONE_STATE");
		phone.add("android.permission.CALL_PHONE");
		phone.add("android.permission.READ_CALL_LOG");
		phone.add("android.permission.WRITE_CALL_LOG");
		phone.add("android.permission.ADD_VOICEMAIL");
		phone.add("android.permission.USE_SIP");
		phone.add("android.permission.PROCESS_OUTGOING_CALLS");
		permissions.add(phone);
		
		bodySensor.add("android.permission.BODY_SENSORS");
		permissions.add(bodySensor);
		
		sms.add("android.permission.SEND_SMS");
		sms.add("android.permission.RECEIVE_SMS");
		sms.add("android.permission.READ_SMS");
		sms.add("android.permission.RECEIVE_WAP_PUSH");
		sms.add("android.permission.RECEIVE_MMS");
		permissions.add(sms);
		
		storage.add("android.permission.READ_EXTERNAL_STORAGE");
		storage.add("android.permission.WRITE_EXTERNAL_STORAGE");
		permissions.add(storage);
		
		//注意这里的permission的value中包含key的一份拷贝
		for (List<String> group : permissions) {
			for (String permission : group) {
				map.put(permission, group);
			}
		}
	}
	
	public boolean contains(String permission) {
		return map.containsKey(permission);
	}
	
	public List<String> getGroup(String permission) {
		return map.get(permission);
	}
	
	public boolean sameGroup(String a, String b) {
		return map.get(a).equals(map.get(b));
	}
	
	public static DangerousPermission instance = new DangerousPermission();
	
	public static DangerousPermission v() {
		return instance;
	}
}
