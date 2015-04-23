package protocol;


import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JPanel;

public class GraphData extends JPanel {
	Integer[] timeRSA;
	Integer[] timeAES;
	
	Integer[] sizeRSA;
	Integer[] sizeAES;
	
	int PAD = 20;
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		try{
			parseData();
		}catch (Exception e){
			e.printStackTrace();
		}
		
		Graphics2D g2 = (Graphics2D)g;
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);
		
		int w = getWidth();
		int h = getHeight();

		g2.draw(new Line2D.Double(PAD, PAD, PAD, h-PAD));
		
		g2.draw(new Line2D.Double(PAD, h-PAD, w-PAD, h-PAD));

		int timeMax = Math.max(getMax(timeAES), getMax(timeRSA));
		int sizeMax = Math.max(getMax(sizeAES), getMax(sizeRSA));

		double xInc = (double)(w - 2*PAD)/(sizeRSA.length-1);
		
		double xScale = (double)(w - 2*PAD)/sizeMax;
		double yScale = (double)(h - 2*PAD)/timeMax;
		
		g2.setPaint(Color.red);
		for(int i = 0; i < sizeRSA.length; i++) {
			double x = sizeRSA[i] * xScale + PAD;
			double y = timeRSA[i] * yScale + PAD;
			g2.fill(new Ellipse2D.Double(x, y, 4, 4));
        }
		
		g2.setPaint(Color.blue);
		for(int i = 0; i < sizeAES.length; i++) {
			double x = sizeAES[i] * xScale + PAD;
			double y = timeAES[i] * yScale + PAD;
			g2.fill(new Ellipse2D.Double(x, y, 4, 4));
        }
    }

	private int getMax(Integer[] data) {
        int max = -Integer.MAX_VALUE;
        for(int i = 0; i < data.length; i++) {
            if(data[i] > max)
                max = data[i];
        }
        return max;
    }
 
	public void parseData() throws NumberFormatException, IOException{
		File dataFile = new File("outputResults");
		BufferedReader fileIn = new BufferedReader(new InputStreamReader
				(new FileInputStream(dataFile)));
		
		String fileLine;
		List<Integer> rsaTime = new ArrayList<Integer>();
		List<Integer> aesTime = new ArrayList<Integer>();
		List<Integer> rsaSize = new ArrayList<Integer>();
		List<Integer> aesSize = new ArrayList<Integer>();
		
		while((fileLine = fileIn.readLine()) != null){
			String timeString = fileLine.substring(fileLine.indexOf("Time"), 
					fileLine.indexOf("Size"));
			timeString = timeString.replaceAll("\\D", "");
			int time = Integer.parseInt(timeString);
			String sizeString = fileLine.substring(fileLine.indexOf("Size"));
			sizeString = sizeString.replaceAll("\\D", "");
			int size = Integer.parseInt(sizeString);
			
			if(fileLine.contains("RSA")){
				rsaTime.add(time);
				rsaSize.add(size);
			}else if(fileLine.contains("AES")){
				aesTime.add(time);
				aesSize.add(size);
			}
		}
		
		timeRSA = listToArray(rsaTime);
		timeAES = listToArray(aesTime);
		sizeRSA = listToArray(rsaSize);
		sizeAES = listToArray(aesSize);
		System.out.println();
	}
    public static void main(String[] args) {
        
    	JFrame f = new JFrame();
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.add(new GraphData());
        f.setSize(400,400);
        f.setLocation(200,200);
        f.setVisible(true);
    }

    public Integer[] listToArray(List<Integer> list){
    	Integer[] array = new Integer[list.size()];
    	for(int i = 0; i < list.size(); i++){
    		array[i] = list.get(i);
    	}
    	return array;
    }
}