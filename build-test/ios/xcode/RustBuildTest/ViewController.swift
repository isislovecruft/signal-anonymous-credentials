//
//  ViewController.swift
//  RustBuildTest
//
//  Created by isis on 8/28/18.
//  Copyright © 2018 Signal. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var textBox: UITextView!
    @IBOutlet weak var buttonHandler: UIButton!
    @IBAction func buttonAction(_ sender: Any) {
        self.doMaths()
    }

    func doMaths() {
        let rustyStuff = DoThingsWithMaths()
        let point = rustyStuff.doThings()

        let encoded = point.map{ String(format: "0x%02X ", $0) }.joined()

        print("The calculated Ristretto point was:\n\(encoded)")

        self.textBox.text = "The calculated Ristretto point was:\n\n\(encoded)"
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        self.buttonHandler.layer.cornerRadius = 10
        self.buttonHandler.clipsToBounds = true

        self.textBox.font = UIFont(name: "Courier", size: 14)

        self.doMaths()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

