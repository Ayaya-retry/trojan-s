pub fn search_u8_vec(left: &Vec<u8>, right: &Vec<u8>) -> Option<usize> {
    if left.is_empty() || right.is_empty() {
        return None;
    }

    for i in 0..left.len() {
        if right.len() > left.len() - i {
            return None;
        }

        if left[i] == right[0] {
            if left[i..i + right.len()] == *right {
                return Some(i);
            }
        }
    }

    None
}
