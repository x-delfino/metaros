
pub fn lcm(n1: &usize, n2: &usize) -> usize {
    n1 * n2 / gcd(n1, n2)
}

pub fn gcd(n1: &usize, n2: &usize) -> usize {
    let mut max: usize;
    let mut min: usize;
    if n1 > n2 {
        max = *n1;
        min = *n2;
    } else {
        max = *n2;
        min = *n1;
    }
    loop {
        let res = max % min;
        if res == 0 {
            return min;
        }

        max = min;
        min = res;
    }
}


