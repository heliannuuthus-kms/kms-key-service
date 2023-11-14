// ge limit pop the last and the last is next, eq limit pop the last and the
// next is None, else None
#[macro_export]
macro_rules! paginated_result {
    ($result:expr, $limit:expr) => {{
        let next = match $result.len().cmp(&($limit as usize)) {
            std::cmp::Ordering::Less => None,
            std::cmp::Ordering::Equal => {
                $result.pop();
                None
            }
            std::cmp::Ordering::Greater => {
                $result.pop().map(|tail| datasource::to_next(tail.id))
            }
        };

        Ok(PaginatedResult {
            next,
            data: $result,
        })
    }};
}

#[macro_export]
macro_rules! pagin {
    ($db:expr, $paginator:expr, $find:expr, $error_msg:expr) => {{
        let mut cursor = $find;

        if let Some(next) = &$paginator.next {
            let id = datasource::from_next(&next).unwrap_or(1);
            cursor.after(id - 1);
        }
        Ok(cursor
            .first($paginator.limit.unwrap_or(10) + 1)
            .all($db)
            .await
            .context($error_msg)?)
    }};
}
