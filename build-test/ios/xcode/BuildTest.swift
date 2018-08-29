//
//  BuildTest.swift
//
//
//  Created by isis on 8/28/18.
//

import Foundation

class DoThingsWithMaths {
    func doThings() -> Data {
        let result = do_things_with_maths()
        let swift_result = Data.init(bytes: result!, count: 32)

        // free(result)

        return swift_result
    }
}
